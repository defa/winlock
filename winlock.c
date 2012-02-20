#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <openssl/evp.h>

#define FILENAME "FOOBAR.JPGENX"

void hexdump (void *ptr, int buflen);
int16_t makekey (unsigned char *key, const unsigned char *pass,
		 int32_t length);
int32_t tryKey (const unsigned char *key, const unsigned char *crypted,
		int32_t * cryptedl, const unsigned char *challenge);

const unsigned char iv[] = "1631330216313302";

int
main (int argc, char *argv[])
{

  unsigned char key[0x20];

  // we open the file
  FILE *fh = fopen (FILENAME, "r");
  fseek (fh, 4, SEEK_CUR);	// jump over first 4 bytes
  // int32_t hintlength = 0;
  // fread (&hintlength, sizeof (int32_t), 1, fh);
  //printf ("Hint is %d (%#x) long - jumping over it\n", hintlength, hintlength);
  // fseek (fh, hintlength, SEEK_CUR);
  int32_t origfilenamelength = 0;
  fread (&origfilenamelength, sizeof (int32_t), 1, fh);
  printf ("Original filename is %d (%#x)long - jumping over it\n",
	  origfilenamelength, origfilenamelength);
  fseek (fh, origfilenamelength + sizeof (int32_t), SEEK_CUR);
  int32_t challengel = 0x14;	// length of sha1 hash
  // fread (&challengel, sizeof (int32_t), 1, fh);
  fseek (fh, sizeof (int32_t), SEEK_CUR);
  printf ("Challenge is %d long - reading it\n", challengel);
  unsigned char *challenge[100];
  memset (challenge, 0, 100);
  fread (challenge, 1, challengel, fh);

  printf ("challenge:\n");
  hexdump (challenge, challengel);

  unsigned char *crypted[100];
  int32_t cryptedl = 0x18;

  memset (crypted, 0, 100);
  fread (crypted, 1, cryptedl, fh);
  printf ("crypted:\n");
  hexdump (crypted, cryptedl);

  fclose (fh);
  FILE *wlh;
  wlh = fopen (argv[1], "r");
  if (NULL == wlh)
    {
      printf ("No wordlist given. Usage: %s <wordlist>\n", argv[0]);
      return 0;
    }
  unsigned char pass[100];
  unsigned char tmpass[100];
  uint32_t i = 0;

  while (fgets (pass, 100, wlh))
    {
      uint32_t passl = strlen (pass);
      pass[passl - 1] = 0;
      passl--;
      char number[3];
      uint32_t numberl = passl + 2;
      int j = 0;
      for (j=0; j <= 100; j++)
	{
	  if (0 == j)
	    {
	      strncpy (tmpass, pass, 100);
	      makekey (key, tmpass, passl);
              j += 120; 
	    }
	  else
	    {
	      number[0] = j / 10 + 0x30;
	      number[1] = j % 10 + 0x30;
	      number[2] = 0;
	      strncpy (tmpass, pass, 100);
	      strcat (tmpass, number);
	      //printf ("%s\n", tmpass);
	      makekey (key, tmpass, numberl);
	    }
	  if (0 == tryKey (key, crypted, &cryptedl, challenge))
	    {
	      printf ("found pass! its: %s\n", tmpass);
              return 0;
	    }
	  if (!(i % 10000))
	    {
	      printf ("%d passwords tested. current try: %s\n", i, tmpass);
	    }
	  i++;
	}
    }

  return 0;
}

int16_t
makekey (unsigned char *key, const unsigned char *pass, int32_t length)
{
  EVP_MD_CTX mdctx;
  EVP_CIPHER_CTX cictx;
  EVP_MD_CTX_init (&mdctx);
  EVP_CIPHER_CTX_init (&cictx);

  unsigned char key2[24];
  unsigned char out[100];
  int outl = 0x10;
  int keyl = 0x18;

#ifdef DEBUG
  printf("%s\n",pass);
#endif

  // initialize SSL
  EVP_MD_CTX_init (&mdctx);
  EVP_CIPHER_CTX_init (&cictx);
  memset (key2, 0x01, 24);
  OpenSSL_add_all_digests ();

  // create the md5 hash of the password
  EVP_DigestInit_ex (&mdctx, EVP_md5 (), NULL);
  EVP_DigestUpdate (&mdctx, pass, length);
  EVP_DigestFinal_ex (&mdctx, out, &outl);
  EVP_MD_CTX_cleanup (&mdctx);

  //copy the md5 hash to the beginning of the key, leave the rest filled with 0x01
  memcpy (key2, out, 0x10);
  // printf("%s line %d\n", __FUNCTION__, __LINE__);

  //encrypt the key2 with itself
  OpenSSL_add_all_ciphers ();
  EVP_EncryptInit_ex (&cictx, EVP_aes_192_cfb (), 0, key2, iv);
  EVP_EncryptUpdate (&cictx, key, &keyl, key2, 0x18);
  EVP_EncryptFinal_ex (&cictx, key, &keyl);
  EVP_CIPHER_CTX_cleanup (&cictx);


  // now we have the key in 'result'
  // printf ("key:\n");
  // hexdump (key, 0x18);
  EVP_cleanup ();

  return keyl;
}

int32_t
tryKey (const unsigned char *key, const unsigned char *crypted,
	int32_t * cryptedl, const unsigned char *challenge)
{
  EVP_MD_CTX mdctx;
  EVP_CIPHER_CTX cictx;
  EVP_MD_CTX_init (&mdctx);
  EVP_CIPHER_CTX_init (&cictx);

  int32_t randdatal = 0x18;
  unsigned char randdata[0x24];

  EVP_DecryptInit_ex (&cictx, EVP_aes_192_cfb (), NULL, key, iv);
  EVP_DecryptUpdate (&cictx, randdata, &randdatal, crypted, *cryptedl);
  EVP_DecryptFinal_ex (&cictx, randdata, &randdatal);
  EVP_CIPHER_CTX_cleanup (&cictx);
  //printf ("randdata (%p):\n", randdata);
  //hexdump (randdata, 0x18);

  unsigned char sha1[0x18];
  int32_t sha1l = 0x14;

  // create the sha1 hash of the decrypted randdata 
  memset (&mdctx, 0, sizeof (EVP_MD_CTX));
  EVP_DigestInit_ex (&mdctx, EVP_sha1 (), NULL);
  EVP_DigestUpdate (&mdctx, randdata, 0x18);
  EVP_DigestFinal_ex (&mdctx, sha1, NULL);
  EVP_MD_CTX_cleanup (&mdctx);

  //printf ("sha1:\n");
  //hexdump (sha1, sha1l);
  EVP_cleanup ();

  return strncmp (sha1, challenge, sha1l);
}


void
hexdump (void *ptr, int buflen)
{
  unsigned char *buf = (unsigned char *) ptr;
  int i, j;
  for (i = 0; i < buflen; i += 16)
    {
      printf ("%06x: ", i);
      for (j = 0; j < 16; j++)
	if (i + j < buflen)
	  printf ("%02x ", buf[i + j]);
	else
	  printf ("   ");
      printf (" ");
      for (j = 0; j < 16; j++)
	if (i + j < buflen)
	  printf ("%c", isprint (buf[i + j]) ? buf[i + j] : '.');
      printf ("\n");
    }
}
