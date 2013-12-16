#include "aes_common.h"

cryptInit getCryptInitFunc(int forEncryption) {
	if (forEncryption == 1) {
		return EVP_EncryptInit_ex;
	} else {
		return EVP_DecryptInit_ex;
	}
}

cryptUpdate getCryptUpdateFunc(int forEncryption) {
	if (forEncryption == 1) {
		return EVP_EncryptUpdate;
	} else {
		return EVP_DecryptUpdate;
	}
}

cryptFinal getCryptFinalFunc(int forEncryption) {
	if (forEncryption == 1) {
		return EVP_EncryptFinal_ex;
	} else {
		return EVP_DecryptFinal_ex;
	}
}