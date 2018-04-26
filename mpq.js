var fs = require("fs");
var decodeImplode = require('implode-decoder')

var fileName = "Eden_RPG_S2_3.0C.w3x"

const constants = {
	ID_MPQ_USERDATA: 0x1B51504D,
	ID_MPQ: 0x1A51504D,

	hash_types : {
        'TABLE_OFFSET': 0,
        'HASH_A': 1,
        'HASH_B': 2,
        'TABLE': 3
    },
    encryption: {
    	HASH_TABLE_KEY: '(hash table)',
    	BLOCK_TABLE_KEY: '(block table)'
    },
    FILE: {
    	IMPLODE: 0x00000100,
    	COMPRESSED: 0x00000200,
    	ENCRYPTED: 0x00010000,
    	FIX_KEY: 0x00020000,
    	SINGLE_UNIT: 0x01000000,
    	DELETE_MARKER: 0x02000000,
    	SECTOR_CRC: 0x04000000,
    	EXISTS: 0x80000000
    },
    MPQ_HEADER_SIZE_V1: 0x20,
    MPQ_FLAG_MALFORMED: 0x00000004,
    MPQ_STRONG_SIGNATURE_SIZE: 256,
    MPQ_STRONG_SIGNATURE_ID: 0x5349474E,
    BLOCK_INDEX_MASK: 0x0FFFFFFF,
    MD5_DIGEST_SIZE: 0x10
}



class MPQHeader {
	constructor (buffer, offset) {
		this.offset = offset;
		this.buffer = buffer

		buffer.read(offset); // advance file buffer

		this.id = buffer.readUIntLE(4);
		if (this.id != constants.ID_MPQ) throw Error("Invalid buffer")

		this.headerSize = buffer.readUIntLE(4);
		this.archiveSize = buffer.readUIntLE(4); //deprecated
		this.version =  buffer.readUIntLE(2);
		this.sectorSize = buffer.readUIntLE(2);
		this.hashTablePos = buffer.readUIntLE(4);
		this.blockTablePos = buffer.readUIntLE(4);
		this.hashTableSize = buffer.readUIntLE(4);
		this.blockTableSize = buffer.readUIntLE(4);
		this.hiblockTablePos64 = 0;
		this.hiHashTablePos = 0;
		this.hiBlockTablePos = 0;
		this.archiveSize64 = 0;
		this.betTablePos64 = 0;
		this.hetTablePos64 = 0;
		this.hashTableSize64 = 0;
		this.blockTableSize64 = 0;
		this.hiBlockTableSize64 = 0;
		this.hetTableSize64 = 0;
		this.betTableSize64 = 0;
		this.rawChunkSize = 0;
		this.oldSectorSize = this.sectorSize


		if (this.version > 4) {
			console.warn("Invalid header version: " + this.version, " will attempt forcing v1");
			this.version = 0;
			this.headerSize = constants.MPQ_HEADER_SIZE_V1
			this.malformed = true;
		}

		if (this.version == 0) {
			assert(this.headerSize == 0x20, "Invalid size for version 0: " + this.headerSize);

			this.fixProtectors(); // protectors put garbage

			assert(this.sectorSize != 0, "Invalid sector size")

		}

		if (this.version == 1) {
			this.hiblockTablePos64 = buffer.readUIntLE(8);
			this.hiHashTablePos = buffer.readUIntLE(4);
			this.hiBlockTablePos = buffer.readUIntLE(4);
		}

		if (this.version == 2) {
			this.archiveSize64 = buffer.readUIntLE(8);
			this.betTablePos64 = buffer.readUIntLE(8);
			this.hetTablePos64 = buffer.readUIntLE(8);
		}

		if (this.version == 3) {
			this.hashTableSize64 = buffer.readUIntLE(8);
			this.blockTableSize64 = buffer.readUIntLE(8);
			this.hiBlockTableSize64 = buffer.readUIntLE(8);
			this.hetTableSize64 = buffer.readUIntLE(8);
			this.betTableSize64 = buffer.readUIntLE(8);
			this.rawChunkSize = buffer.readUIntLE(4);

			this.md5 = {
				blockTable: buffer.read(10),
				hashTable: buffer.read(10),
				hiBlockTable: buffer.read(10),
				betTable: buffer.read(10),
				hetTable: buffer.read(10),
				mpqHeader: buffer.read(10)
			}

		}

		if([this.hetTablePos64, this.betTablePos64, (this.hiHashTablePos << 32) | this.hashTablePos, (this.hiBlockTablePos << 32) | this.blockTablePos, this.hiblockTablePos64].filter(n => n && this.offset + n > this.buffer.length).length) {
			throw Error("Bad format")
		}

		if (this.hashTableSize == 0 && this.hetTableSize64 == 0) throw Error("No het or hash table found");


	}

	fixProtectors () {

		if (this.blockTableSize > 1) {
			if (this.hashTablePos <= this.headerSize || this.hashTablePos & 0x80000000) {
				this.malformed = true;
			}
			if (this.blockTablePos <= this.headerSize || this.blockTablePos & 0x80000000) {
				this.malformed = true;
			}
		}

		if (this.sectorSize & 0xFF00) { //only first byte is used by w3
			this.sectorSize = this.sectorSize & 0xFF;
			this.malformed = true;
		}

		this.archiveSize64 = this.archiveSize;

		//this.blockTablePos64 = (this.blockTablePos + this.offset) >>> 0;

		if (this.malformed) {
			this.archiveSize64 = this.fixArchiveSize();
			this.archiveSize = this.archiveSize64;
		}

		//antioverflow
		this.blockTableSize &= constants.BLOCK_INDEX_MASK;
		this.hashTableSize &= constants.BLOCK_INDEX_MASK;

		this.sectorSize = 0x200 << this.sectorSize;

		this.blockTableSize = Math.min(this.blockTableSize, this.hashTableSize);

		this.blockTableSize64 = (this.blockTableSize * 16) >>> 0;
		this.hashTableSize64 = (this.hashTableSize * 16) >>> 0;

	}

	fixArchiveSize () {
		if (this.blockTablePos < this.archiveSize) {
			if(this.archiveSize - this.blockTablePos == this.blockTableSize * 16)
            	return this.archiveSize;
            if (this.archiveSize == this.buffer.length - this.offset)
            	return this.archiveSize;
		}

		if(this.buffer.length - this.offset > constants.MPQ_STRONG_SIGNATURE_SIZE + 4) {
			var signature = this.buffer.buffer.slice(this.buffer.length - constants.MPQ_STRONG_SIGNATURE_SIZE - 4, this.buffer.length - constants.MPQ_STRONG_SIGNATURE_SIZE).readUIntLE(0, 4);

			if (signature == constants.MPQ_STRONG_SIGNATURE_ID) {
				return this.buffer.length - constants.MPQ_STRONG_SIGNATURE_SIZE - 4
			}
		}

		return this.buffer.length - this.offset;
	}

}


class BlockTableEntry {
	constructor (data) {
		Object.assign(this, data);
	}

	exists () {
		return this.flags & constants.FILE.EXISTS
	}

	isCompressed () {
		return this.flasg & constants.FILE.COMPRESSED
	}

	isEncrypted () {
		return this.flasg & constants.FILE.ENCRYPTED;
	}

	isSingle () {
		return this.flags & constants.FILE.SINGLE_UNIT;
	}

	isImploded () {
		return this.flags & constants.FILE.MPQ_FILE_IMPLODE;
	}
}

class Table {
	constructor (mpq, type, key) {
		this.offset = mpq.header.offset + mpq.header[type + "TablePos"];
		this.entriesQty = mpq.header[type + "TableSize"];

		this.key = mpq.encryption.hash(key, 'TABLE');
		this.buffer = mpq.encryption.decrypt(mpq.file.slice(this.offset, this.offset + this.entriesQty * 16), this.key);

		this.entries = []


		for (var i = 0; i < this.entriesQty; i++) {
			this.entries.push(this.readEntry())
		}

		this.encryption = mpq.encryption;
	}
}

class blockTable extends Table {
	constructor (mpq) {
		super(mpq, "block", constants.encryption.BLOCK_TABLE_KEY)
	}

	readEntry () {
		return new BlockTableEntry({
            offset: this.buffer.readUIntLE(4),
            compressedSize: this.buffer.readUIntLE(4),
            size: this.buffer.readUIntLE(4),
            flags: this.buffer.readUIntLE(4)
        })
	}

	getEntry (idx) {
		return this.entries[idx];
	}
}

class HashTable extends Table {
	constructor (mpq) {
		super(mpq, "hash", constants.encryption.HASH_TABLE_KEY)
	}

	readEntry () {
		return {
            hashA: this.buffer.readUIntLE(4),
            hashB: this.buffer.readUIntLE(4),
            locale: this.buffer.readUIntLE(4),
            platform: this.buffer.readUIntLE(2),
            blockTableIndex: this.buffer.readUIntLE(2)
        }
	}


	getEntry (fileName) {
		var hashA = this.encryption.hash(fileName, 'HASH_A')
        var hashB = this.encryption.hash(fileName, 'HASH_B')

        console.log(hashA, hashB)

       	for (var i = 0; i < this.entries.length; i++) {
       		if (this.entries[i].hashA == hashA && this.entries[i].hashB == hashB) return this.entries[i];
       	}
	}	
}


class Encryption {
	constructor () {
		var seed = 0x00100001;

		this.encryptionTable = {}

		for (var i = 0; i < 256; i++) {
			var index = i;

			for (var j = 0; j < 5; j++) {
				seed = (seed * 125 + 3) % 0x2AAAAB
                var temp1 = (seed & 0xFFFF) << 0x10

                seed = (seed * 125 + 3) % 0x2AAAAB
                var temp2 = (seed & 0xFFFF)

                this.encryptionTable[index] = (temp1 | temp2) >>> 0

                index += 0x100
			}
		}
	}




	decrypt(dataBuffer, key) {
	    var seed = 0xEEEEEEEE >>> 0;

	    var length = dataBuffer.length / 4;
	    var offset = 0;

	    var result = new Buffer(dataBuffer.length);
	    result.fill(' ');

	    for (var i = 0; i < length; i++) {
	        var encryptTableValue = this.encryptionTable[0x400 + (key & 0xFF)];
	        seed += encryptTableValue;

	        var a = dataBuffer.readUInt32LE(offset);
	        var b = key + seed;
	        var ch = (a ^ b) >>> 0;

	        var x = (~key << 0x15) + 0x11111111;
	        var y = key >>> 0x0B;
	        key = (x | y) >>> 0;

	        seed = ch + seed + (seed << 5) + 3;

	        result.writeUInt32LE(ch, offset);

	        offset += 4;
	    }

	    return new BufferWrapper(result);
	}


	hash(str, hash_type){
	 	var seed1 = 0x7FED7FED >>> 0;
	    var seed2 = 0xEEEEEEEE >>> 0;

	    str = str.toUpperCase();

	    for (var i = 0; i < str.length; i++) {
	        var ch = str.charCodeAt(i);

	        var a = this.encryptionTable[constants.hash_types[hash_type] * 0x100 + ch];
	        var b = seed1 + seed2;
	        seed1 = (a ^ b) >>> 0;
	        seed2 = ch + seed1 + seed2 + (seed2 << 5) + 3;
	    }

	    return seed1;
	}

}


class MPQ {

	constructor (fileName) {
		this.file = fs.readFileSync(fileName);

		var idx = 0;

		var found = false;

		while(idx < this.file.length) {
			var chunk = this.file.slice(idx, idx + 512);
			var id = chunk.slice(0, 4).readUIntLE(0, 4);

			if (id == constants.ID_MPQ) {
				found = true;
				break;
			}

			idx += 512;

		}

		if (found) {
			this.header = new MPQHeader(new BufferWrapper(this.file), idx);
			this.encryption = new Encryption();
			this.hashTable = new HashTable(this);
			this.blockTable = new blockTable(this);
		} else {
			throw Error("mpq header not found")
		}

	}

	getBlockEntry (fileName) {
		var hashEntry = this.hashTable.getEntry(fileName);

		assert(hashEntry != null, "File not found in hashTable: " + fileName);

		var blockEntry = this.blockTable.getEntry(hashEntry.blockTableIndex);

		assert(blockEntry.exists(), "File does not exist: " + fileName);

		return blockEntry;
	}

	read (fileName) {
		var blockEntry = this.getBlockEntry(fileName);

		var buffer = this.file.slice(blockEntry.offset, blockEntry.offset + blockEntry.compressedSize);

		if (!blockEntry.isEncrypted() && !blockEntry.isCompressed()) {
			return buffer;
		}

		throw new Error("Not Supported")

		if (blockEntry.isSingle()) {
			if (blockEntry.isImploded()) {
				return fs.createReadStream(buffer).pipe(decodeImplode());
			}	
		}
	}

}



class BufferWrapper {

	constructor (buffer) {
		this.idx = 0;
		this.buffer = buffer;
		this.bytesRead = 0;
		this.length = buffer.length
	}

	read (bytes) {
		this.idx += bytes;
		this.bytesRead += bytes;
		return this.buffer.slice(this.idx - bytes, this.idx);
	}

	peek (bytes) {
		return this.buffer.slice(this.idx, this.idx + bytes);
	}

	toString (...args) {
		return this.buffer.toString.apply(this.buffer, arguments);
	}

	readableLength () {
		return this.buffer.length - this.idx;
	}

	readUIntLE (len) {
		return this.read(len).readUIntLE(0, len);
	}

}

function assert(cond, msg) {
	if (!cond) throw Error(msg);
}

var mpq = new MPQ (fileName);

mpq.read('scripts/war3map.j')