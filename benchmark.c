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


  //int in_recip[5] = {4, 5, 6, 7, 8 };
  //int num_recip = 5;
  //int rems[3] = { 5, 6, 7 };
  //int N_rems = 3;
  //int adds[12] = { 2, 3, 5, 6, 7, 10, 11, 12, 13, 14, 15, 16 };
  //int N_adds = 12;
  // FINAL ELEMENTS IN PRODUCT SHOULD BE 2-8, & 10-16

  /*
  Gen_encr_prod_from_indicies(gbs, sys2, in_recip, num_recip);

  if(DEBUG) {
    PrintBitString(sys2->recipients,BSL);
    printf("\nsys2 encr_product = ");
    element_out_str(stdout, 0, sys2->encr_prod);
    printf("\n");
  }

  Change_encr_prod_indicies(gbs, sys2, adds, N_adds, rems, N_rems);
  if(DEBUG) {
    PrintBitString(sys2->recipients,BSL);
    printf("\nsys2 encr_product = ");
    element_out_str(stdout, 0, sys2->encr_prod);
    printf("\n");
  }


  if(DEBUG) {
    PrintBitString(sys->recipients,BSL);
    printf("\nsys1 encr_product = ");
    element_out_str(stdout, 0, sys->encr_prod);
  }
  */

  //if(DEBUG && 0) printf("\ndone 1 decr\n");
  //if(DEBUG && 0) printf("\ndone 2 decr\n");
  //Gen_decr_prod_from_bitvec(gbs, 2, recip, &mykey3);
  //if(DEBUG && 0) printf("\ndone 3 decr\n");
  //Gen_decr_prod_from_indicies(gbs, 2, in_recip, num_recip, &mykey2);
  //Change_decr_prod_indicies(gbs, 2, adds, N_adds, rems, N_rems, &mykey2);

  //Gen_decr_prod_from_bitvec(gbs, 2, recip, &mykey3);

/*
  if(0 && DEBUG) {
    printf("\n");
    printf("mykey1 decr_product = ");
    element_out_str(stdout, 0, mykey.decr_prod);
    printf("\n");
  }
  if(DEBUG && 0) {
    printf("\n");
    printf("\n");
  }
  if(DEBUG && 0) {
    printf("\n");
    printf("\n");
  }




  //TESTING FOR SINGLE KEY LOAD AND STORE
  priv_key_t load_key = (priv_key_t)pbc_malloc(sizeof(struct single_priv_key_s));

  StorePrivKey("key2.stor", &mykey);
  LoadPrivKey("key2.stor", &load_key, gbs);

  if(DEBUG) {
    printf("\nold = ");
    element_out_str(stdout, 0, mykey.g_i_gamma);
    printf("\nnew = ");
    element_out_str(stdout, 0, load_key->g_i_gamma);
    printf("\nold = ");
    element_out_str(stdout, 0, mykey.g_i);
    printf("\nnew = ");
    element_out_str(stdout, 0, load_key->g_i);
    printf("\nold = ");
    element_out_str(stdout, 0, mykey.h_i);
    printf("\nnew = ");
    element_out_str(stdout, 0, load_key->h_i);
    printf("\nold = ");
    element_out_str(stdout, 0, mykey.decr_prod);
    printf("\nnew = ");
    element_out_str(stdout, 0, load_key->decr_prod);
    printf("\n index = %d", mykey.index);
    printf("\n index = %d", load_key->index);
  }

  ct_t myCT2 = (ct_t) pbc_malloc(sizeof(struct ciphertext_s));
  ct_t myCT3 = (ct_t) pbc_malloc(sizeof(struct ciphertext_s));
  //int recip2[14] = { 2, 3, 4, 5, 6, 7, 8, 10, 11, 12, 13, 14, 15, 16 };
  //int n_recip2 = 14;
  element_t key1;
  element_t key2;
  element_t key3;
  element_t key4;
  element_t key5;
  element_t key6;

  BroadcastKEM_using_product(gbs, sys, myCT3, key3);
  BroadcastKEM_using_product(gbs, sys, myCT2, key2);


  //BroadcastKEM_using_bitvec(gbs, sys, recip, myCT2, key2);
  //BroadcastKEM_using_indicies(gbs, sys, myCT3, recip2, n_recip2, key3);


  if(DEBUG) {
    //COMPARE ALL THREE CTs!
    printf("\n1-C0 = ");
    element_out_str(stdout, 0, myCT->C0);
    printf("\n2-C0 = ");
    element_out_str(stdout, 0, myCT2->C0);
    printf("\n3-C0 = ");
    element_out_str(stdout, 0, myCT3->C0);
    printf("\n1-C1 = ");
    element_out_str(stdout, 0, myCT->C1);
    printf("\n2-C1 = ");
    element_out_str(stdout, 0, myCT2->C1);
    printf("\n3-C1 = ");
    element_out_str(stdout, 0, myCT3->C1);
  }


  printf("\nkey1 = ");
  element_out_str(stdout, 0, key1);
  printf("\n");
  printf("\nkey2 = ");
  element_out_str(stdout, 0, key2);
  printf("\n");
  printf("\nkey3 = ");
  element_out_str(stdout, 0, key3);
  printf("\n");

  //PrintBitString(mykey.recipients, BSL);
  //DecryptKEM_using_product(gbs, &mykey2, key5, myCT2);


  //printf("\nmyprivkey = ");
  //element_out_str(stdout, 0, mykey.g_i_gamma);
  //printf("\n");
  printf("\nkey1 = ");
  element_out_str(stdout, 0, key4);
  printf("\n");
  printf("\nkey2 = ");
  element_out_str(stdout, 0, key5);
  printf("\n");
  printf("\nkey3 = ");
  element_out_str(stdout, 0, key6);
  printf("\n");
*/
  return 0;
}

