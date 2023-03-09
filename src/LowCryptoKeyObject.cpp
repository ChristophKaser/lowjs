// -----------------------------------------------------------------------------
//  LowCryptoKeyObject.cpp
// -----------------------------------------------------------------------------

#include "LowCryptoKeyObject.h"
#include "psa/crypto.h"



// -----------------------------------------------------------------------------
//  LowCryptoKeyObject::LowCryptoKeyObject
// -----------------------------------------------------------------------------

LowCryptoKeyObject::LowCryptoKeyObject(low_t *low, int keyId)
                             :
    mLow(low), mKeyId(keyId), mIndex(-1)
{
}

// -----------------------------------------------------------------------------
//  LowCryptoKeyObject::~LowCryptoKeyObject
// -----------------------------------------------------------------------------

LowCryptoKeyObject::~LowCryptoKeyObject()
{
    psa_destroy_key(mKeyId);
    if(mIndex >= 0)
    {
        if(mIndex >= mLow->cryptoKeyObjects.size() ||
           mLow->cryptoKeyObjects[mIndex] != this)
            printf("assertion error at LowCrypLowCryptoKeyObjecttoHash\n");

        mLow->cryptoKeyObjects[mIndex] = NULL;
    }
}
