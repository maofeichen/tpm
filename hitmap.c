#include "hitmap.h"

HitMapContext *
buildHitMap(TPMContext *tpm)
{
    HitMapContext *hitMap;
    TPMBufHashTable *tpmBuf;

    tpmBuf = analyzeTPMBuf(tpm);
    assignTPMBufID(tpmBuf);
    printTPMBufHashTable(tpmBuf);


    return hitMap;
}
