/* Implementation of Boneh-Gentry-Waters broadcast encryption scheme
   Code by:  Matt Steiner   MattS@cs.stanford.edu
   testbce.c
*/

#include <string.h>
#include "pbc_bce.h"

#define N 8192
#define N_DIV_EIGHT  N/8

int main(int argc, char *agrv[]) {
  int i;

  //Global Setup
  global_broadcast_params_t gbs;
  Setup_global_broadcast_params(&gbs, N, "d201.param");
  printf("set global broadcast params\n");

  //Broadcast System Setup
  broadcast_system_t sys;
  Gen_broadcast_system(gbs, &sys);
  printf("gen broadcast system\n");

  //Taget user
  char recip[N_DIV_EIGHT];
  for(i = 0; i < N_DIV_EIGHT; i++)
    recip[i] = 254;

  Gen_encr_prod_from_bitvec(gbs, sys, recip);
  //Product_Is_Right(gbs, sys, recip);

  StoreParams("system.stor", gbs, sys);
  printf("stored sys params\n");

  //Get private key
  struct single_priv_key_s mykey;
  Get_priv_key(gbs, sys, 7, &mykey);
  Gen_decr_prod_from_bitvec(gbs, 7, recip, &mykey);
  StorePrivKey("mykey.stor", &mykey);
  printf("stored private key\n");

  ct_t myCT = (ct_t) pbc_malloc(sizeof(struct ciphertext_s));
  element_t key1;
  BroadcastKEM_using_product(gbs, sys, myCT, key1);
  //StoreCiphertext("cip.store", myCT);
  DecryptKEM_using_product(gbs, &mykey, key1, myCT);


  StoreHdr("hdr.stor", gbs, myCT);

  FreeCT(myCT);
  FreeBCS(sys);
  FreeGBP(gbs);
  FreePK(&mykey);

  return 0;
}

