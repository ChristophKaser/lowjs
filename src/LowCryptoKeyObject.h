// -----------------------------------------------------------------------------
//  LowCryptoKeyObject.h
// -----------------------------------------------------------------------------

#ifndef __LOWCRYPTOKEYOBJECT_H__
#define __LOWCRYPTOKEYOBJECT_H__

#include "low_main.h"

using namespace std;

class LowCryptoKeyObject
{
  public:
    LowCryptoKeyObject(low_t *low, int keyId);
    ~LowCryptoKeyObject();

    int mKeyId;

    void SetIndex(int index) { mIndex = index; }

  private:
    low_t *mLow;
    int mIndex;
};

#endif /* __LOWCRYPTOKEYOBJECT_H__ */