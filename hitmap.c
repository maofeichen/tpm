#include "hitmap.h"

HitMapContext *
buildHitMap(TPMContext *tpm)
{
    HitMapContext *hitMap;
    TPMBufHashTable *tpmBuf;

    tpmBuf = getAllTPMBuf(tpm);
    assignBufID(tpmBuf);
    printTPMBufHT(tpmBuf);


    return hitMap;
}
