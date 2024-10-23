/*
 * GStCrypto
 * Copyright, LCC (C) 2015 RidgeRun, LCC <carsten.behling@ridgerun.com>
 * Copyright, LCC (C) 2016 RidgeRun, LCC <jose.jimenez@ridgerun.com>
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Alternatively, the contents of this file may be used under the
 * GNU Lesser General Public License Version 2.1 (the "LGPL"), in
 * which case the following provisions apply instead of the ones
 * mentioned above:
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1335, USA.
 */

/**
 * SECTION:crypto
 *
 * FIXME:Describe crypto here.
 *
 * <refsect2>
 * <title>Example launch line</title>
 * |[
 * echo "This is a crypto test ... " > plain.txt && gst-launch  filesrc \
 *     location=plain.txt ! crypto mode=enc ! crypto mode=dec ! \
 *     filesink location=dec.txt && cat dec.txt
 *
 * ]|
 * </refsect2>
 */

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <gst/gst.h>
#include <gst/base/gstbasetransform.h>

#include <string.h>

#include "gstcrypto.h"

#include <openssl/provider.h>


GST_DEBUG_CATEGORY_STATIC (gst_crypto_debug);
#define GST_CAT_DEFAULT gst_crypto_debug

#define CIPHER "aes-128-cbc"
#define MAX_KEY_LENGTH  1024
#define MAX_PASS_LENGTH  (MAX_KEY_LENGTH*2+32)

#define DEFAULT_PASS "RidgeRun"
#define DEFAULT_KEY "1f9423681beb9a79215820f6bda73d0f"
#define DEFAULT_IV "e9aa8e834d8d70b7e0d254ff670dd718"

static  OSSL_PROVIDER *prov = NULL;

/* Filter signals and args */
enum
{
  LAST_SIGNAL
};

enum
{
  PROP_0,
  PROP_MODE,
  PROP_CIPHER,
  PROP_PASS,
  PROP_KEY,
  PROP_IV,
};

#define DEBUG
#ifdef DEBUG
  static void debug_log(char* topic, char* msg) {
    printf("gstCrypto-%s: %s \n",topic, msg);
  }
  static void debug_log_hex(char* topic, int v) {
     printf("gstCrypto-%s: %d (0x%04x) \n",topic, v, v);
  }
  #define DEBUG_LOG(o,m) debug_log(o,m);
  #define DEBUG_LOG_HEX(o, v) debug_log_hex(o, (int)v);
#else
  #define DEBUG_LOG(o,m) 
  #define DEBUG_LOG_HEX(o, v)
#endif

/* the capabilities of the inputs and outputs.
 *
 */
static GstStaticPadTemplate sink_template = GST_STATIC_PAD_TEMPLATE ("sink",
    GST_PAD_SINK,
    GST_PAD_ALWAYS,
    GST_STATIC_CAPS ("ANY")
    );

static GstStaticPadTemplate src_template = GST_STATIC_PAD_TEMPLATE ("src",
    GST_PAD_SRC,
    GST_PAD_ALWAYS,
    GST_STATIC_CAPS ("ANY")
    );

#define gst_crypto_parent_class parent_class
G_DEFINE_TYPE (GstCrypto, gst_crypto, GST_TYPE_BASE_TRANSFORM);

static void gst_crypto_set_property (GObject * object, guint prop_id,
    const GValue * value, GParamSpec * pspec);
static void gst_crypto_get_property (GObject * object, guint prop_id,
    GValue * value, GParamSpec * pspec);

static GstFlowReturn gst_crypto_transform (GstBaseTransform * base,
    GstBuffer * inbuf, GstBuffer * outbuf);
/* We have a bigger output buffer than input buffer and have allocate
   that here ... this is somewhat different from 0.10, where we use
   transform_size(...) ... */
static GstFlowReturn gst_crypto_prepare_output_buffer (GstBaseTransform * base,
    GstBuffer * inbuf, GstBuffer ** outbuf);

static gboolean gst_crypto_start (GstBaseTransform * base);
static gboolean gst_crypto_stop (GstBaseTransform * base);

static void gst_crypto_finalize (GObject * object);

/* crypto helper functions */
static gboolean gst_crypto_openssl_init (GstCrypto * filter);
static GstFlowReturn gst_crypto_run (GstCrypto * filter);
static gboolean gst_crypto_pass2keyiv (GstCrypto * filter);

/* general helper functions */
static gboolean gst_crypto_hexstring2number (GstCrypto * filter,
    const gchar * in, gchar * out);
static void remove_padding (guchar * srcplaintext,
    gint data_buff_offset, guint * src_bytes_read);

/* GObject vmethod implementations */

/* initialize the crypto's class */
static void
gst_crypto_class_init (GstCryptoClass * klass)
{
  GObjectClass *gobject_class;
  GstElementClass *gstelement_class;

  gobject_class = (GObjectClass *) klass;
  gstelement_class = (GstElementClass *) klass;

  gobject_class->set_property = gst_crypto_set_property;
  gobject_class->get_property = gst_crypto_get_property;

  g_object_class_install_property (gobject_class, PROP_MODE,
      g_param_spec_string ("mode", "Mode",
          "'enc' for encryption, 'dec' for decryption", "enc",
          G_PARAM_READWRITE | GST_PARAM_CONTROLLABLE));

  g_object_class_install_property (gobject_class, PROP_CIPHER,
      g_param_spec_string ("cipher", "Cipher",
          "cypher string in openssl format, support Quantropi qeep, default aes-128-cbc",
          CIPHER, G_PARAM_READWRITE));
DEBUG_LOG("init_cipher", CIPHER)

  g_object_class_install_property (gobject_class, PROP_PASS,
      g_param_spec_string ("pass", "Pass", "crypto password", DEFAULT_PASS,
          G_PARAM_READWRITE | GST_PARAM_CONTROLLABLE));
DEBUG_LOG("init_pass", DEFAULT_PASS)

  /* The default hexkey is what openssl would generate from the default password
     'RidgeRun' */
  g_object_class_install_property (gobject_class, PROP_KEY,
      g_param_spec_string ("key", "Key",
          "crypto hexkey", (guchar *) DEFAULT_KEY,
          G_PARAM_READWRITE | GST_PARAM_CONTROLLABLE));

  /* The default iv is what openssl would generate from the default password
     'RidgeRun' */
  g_object_class_install_property (gobject_class, PROP_IV,
      g_param_spec_string ("iv", "Iv",
          "crypto initialization vector", (guchar *) DEFAULT_IV,
          G_PARAM_READWRITE | GST_PARAM_CONTROLLABLE));

  gst_element_class_set_details_simple (gstelement_class,
      "Crypto",
      "Generic/Filter",
      "RidgeRun's crypto plugin that encrypts/decrypts data on the fly",
      "Carsten Behling <carsten.behling@ridgerun.com>");

  gst_element_class_add_pad_template (gstelement_class,
      gst_static_pad_template_get (&src_template));
  gst_element_class_add_pad_template (gstelement_class,
      gst_static_pad_template_get (&sink_template));

  gobject_class->finalize = gst_crypto_finalize;

  GST_BASE_TRANSFORM_CLASS (klass)->transform =
      GST_DEBUG_FUNCPTR (gst_crypto_transform);
  GST_BASE_TRANSFORM_CLASS (klass)->prepare_output_buffer =
      GST_DEBUG_FUNCPTR (gst_crypto_prepare_output_buffer);
  GST_BASE_TRANSFORM_CLASS (klass)->start =
      GST_DEBUG_FUNCPTR (gst_crypto_start);
  GST_BASE_TRANSFORM_CLASS (klass)->stop = GST_DEBUG_FUNCPTR (gst_crypto_stop);

  /* debug category for fltering log messages */
  GST_DEBUG_CATEGORY_INIT (gst_crypto_debug, "crypto", 0,
      "crypto encrypt/decrypt element");

DEBUG_LOG("gst_crypto_class_init", "exit")
}

/* initialize the new element
 * initialize instance structure
 */
static void
gst_crypto_init (GstCrypto * filter)
{
  GST_INFO_OBJECT (filter, "Initializing plugin");
DEBUG_LOG("gst_crypto_init", "Initializing")
  filter->mode = g_malloc (64);
  g_stpcpy (filter->mode, "enc");
  filter->is_encrypting = TRUE;
  filter->cipher = g_malloc (64);
  g_stpcpy (filter->cipher, CIPHER);
  filter->pass = g_malloc (MAX_PASS_LENGTH);
  g_stpcpy (filter->pass, DEFAULT_PASS);
  filter->key = g_malloc (MAX_KEY_LENGTH);
  filter->iv = g_malloc (64);
  filter->use_pass = TRUE;
  GST_INFO_OBJECT (filter, "Plugin initialization successfull");
}

static void
gst_crypto_set_property (GObject * object, guint prop_id,
    const GValue * value, GParamSpec * pspec)
{
  GstCrypto *filter = GST_CRYPTO (object);

  GST_DEBUG_OBJECT (filter, "Setting properties");
  switch (prop_id) {
    case PROP_MODE:
      filter->mode = g_value_dup_string (value);
      if (!g_strcmp0 (filter->mode, "enc"))
        filter->is_encrypting = TRUE;
      else if (!g_strcmp0 (filter->mode, "dec"))
        filter->is_encrypting = FALSE;
      break;
    case PROP_CIPHER:
      filter->cipher = g_value_dup_string (value);
      filter->evp_cipher = NULL; // check cipher at opnessl_init step 
// #ifdef AES
//       filter->evp_cipher = EVP_get_cipherbyname (filter->cipher);
// #else
//       if (prov == NULL) {
//         prov = OSSL_PROVIDER_load(libctx, CIPHER);
//       }
//       if ( (prov != NULL) && (libctx != NULL) ) {
//         filter->evp_cipher = EVP_CIPHER_fetch(libctx, CIPHER, NULL);
//       }
// #endif
      break;
    case PROP_PASS:
      filter->pass = g_value_dup_string (value);
      filter->use_pass = TRUE;
      break;
    case PROP_KEY:
       DEBUG_LOG("key_str", g_value_dup_string (value))
      if (!gst_crypto_hexstring2number (filter, g_value_dup_string (value),
              (gchar *) filter->key)) {
        /* If hexkey is invalid, set to default */
        gst_crypto_hexstring2number (filter, DEFAULT_KEY,
            (gchar *) filter->key);
      }
      filter->use_pass = FALSE;
      break;
    case PROP_IV:
      if (!gst_crypto_hexstring2number (filter, g_value_dup_string (value),
              (gchar *) filter->iv)) {
        /* If hexkey is invalid, set to default */
        gst_crypto_hexstring2number (filter, DEFAULT_IV, (gchar *) filter->iv);
      }
      filter->use_pass = FALSE;
      break;
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
      break;
  }
  GST_DEBUG_OBJECT (filter, "mode: %s", filter->mode);
  GST_DEBUG_OBJECT (filter, "cipher: %s", filter->cipher);
  GST_DEBUG_OBJECT (filter, "pass: %s", filter->pass);
  GST_DEBUG_OBJECT (filter, "Set properties succsessfully ");
 
  DEBUG_LOG("cipher", filter->cipher)
  DEBUG_LOG("pass", filter->pass)
}

static void
gst_crypto_get_property (GObject * object, guint prop_id,
    GValue * value, GParamSpec * pspec)
{
  GstCrypto *filter = GST_CRYPTO (object);

  GST_DEBUG_OBJECT (filter, "Getting properties");
  switch (prop_id) {
    case PROP_MODE:
      g_value_set_string (value, filter->mode);
      break;
    case PROP_CIPHER:
      g_value_set_string (value, filter->cipher);
      break;
    case PROP_PASS:
      g_value_set_string (value, filter->pass);
      break;
    case PROP_KEY:
      g_value_set_string (value, (gchar *) filter->key);
      break;
    case PROP_IV:
      g_value_set_string (value, (gchar *) filter->iv);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
      break;
  }
  GST_DEBUG_OBJECT (filter, "Got properties succsessfully ");
}

/* GstBaseTransform vmethod implementations */

/* this function does the actual processing
 */
static GstFlowReturn
gst_crypto_transform (GstBaseTransform * base,
    GstBuffer * inbuf, GstBuffer * outbuf)
{
  GstCrypto *filter = GST_CRYPTO (base);
  GstFlowReturn ret;
  GstMapInfo inmap, outmap;

  gst_buffer_map (inbuf, &inmap, GST_MAP_READ);
  gst_buffer_map (outbuf, &outmap, GST_MAP_WRITE);

  if (GST_CLOCK_TIME_IS_VALID (GST_BUFFER_TIMESTAMP (outbuf)))
    gst_object_sync_values (GST_OBJECT (filter), GST_BUFFER_TIMESTAMP (outbuf));

  if (!inmap.data || !outmap.data)
    return GST_FLOW_ERROR;

  GST_LOG_OBJECT (filter,
      "Transforming, input buffer size %d, output buffer size: %d\n",
      (int) inmap.size, (int) outmap.size);

  if (filter->is_encrypting) {
    filter->plaintext = inmap.data;
    filter->plaintext_len = gst_buffer_get_size (inbuf);
    filter->ciphertext = outmap.data;
  } else {
    filter->plaintext = outmap.data;
    filter->ciphertext = inmap.data;
    filter->ciphertext_len = gst_buffer_get_size (inbuf);
  }
  ret = gst_crypto_run (filter);
  if (filter->is_encrypting) {
    gst_buffer_set_size (outbuf, filter->ciphertext_len);
  } else {
    gst_buffer_set_size (outbuf, filter->plaintext_len);
  }
  GST_LOG_OBJECT (filter, "Plaintext len: %d, Ciphertext len: %d",
      filter->plaintext_len, filter->ciphertext_len);

  gst_buffer_unmap (inbuf, &inmap);
  gst_buffer_unmap (outbuf, &outmap);

  GST_LOG_OBJECT (filter, "Transformation successfull");
  return ret;
}

static GstFlowReturn
gst_crypto_prepare_output_buffer (GstBaseTransform * base,
    GstBuffer * inbuf, GstBuffer ** outbuf)
{
  GstCrypto *filter = GST_CRYPTO (base);
  GST_LOG_OBJECT (filter, "Allocating output buffer size: %d",
      (int) gst_buffer_get_size (inbuf));

  if (filter->is_encrypting)
    *outbuf = gst_buffer_new_allocate (NULL, gst_buffer_get_size (inbuf)
        + EVP_MAX_BLOCK_LENGTH, NULL);
  else
    *outbuf = gst_buffer_new_allocate (NULL, gst_buffer_get_size (inbuf), NULL);

  *outbuf = gst_buffer_make_writable (*outbuf);

  return GST_FLOW_OK;
}

static gboolean
gst_crypto_start (GstBaseTransform * base)
{
  GstCrypto *filter = GST_CRYPTO (base);
  DEBUG_LOG("", "gst_crypto_start")
  GST_INFO_OBJECT (filter, "Starting");

  if (filter->use_pass) {
    //pass overwrite cipher option in this case
    //checking post quantum crypto support via pass for AES cipher backward compatibility 
    //pass with "QISPACE:" prefix, ex pass=QISPACE:QK_Hex_String, use post quantum crypto cipher "qeep" via provider
    //which is same to use option: cipher=qeep, key="QK_Hex_String"
    //For AES-256 case, use option cipher=AES-256-CBC. any cipher list: openssl list  -cipher-algorithms
    if (strstr(filter->pass, "QISPACE:") != NULL ) {
      filter->cipher = "qeep";
    }
  }
  if (!gst_crypto_openssl_init (filter)) {
    GST_ERROR_OBJECT (filter, "Openssl initialization failed");
    return FALSE;
  }

  if (filter->use_pass)
    if (!gst_crypto_pass2keyiv (filter)) {
      GST_ERROR_OBJECT (filter, "Openssl key and iv generation failed");
      return FALSE;
    }

  GST_INFO_OBJECT (filter, "Start successfull");
  DEBUG_LOG("cipher", filter->cipher)
  DEBUG_LOG("mode", filter->mode)
  DEBUG_LOG("pass", filter->pass)
  return TRUE;
}

static gboolean
gst_crypto_stop (GstBaseTransform * base)
{
  GstCrypto *filter = GST_CRYPTO (base);

  if (prov != NULL) {
    OSSL_PROVIDER_unload(prov);
  }

  GST_INFO_OBJECT (filter, "Stopping");
  GST_LOG_OBJECT (filter, "Stop successfull");
  DEBUG_LOG("", "gst_crypto_stop")
  return TRUE;
}

/* Crypto helper  functions */
static gboolean
gst_crypto_openssl_init (GstCrypto * filter)
{
  
  GST_INFO_OBJECT (filter, "Initializing");
DEBUG_LOG("", "gst_crypto_openssl_init")
  ERR_load_crypto_strings ();
  OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
  // OpenSSL_add_all_algorithms ();
  // OPENSSL_config (NULL);
  //load default openssl config here
  OSSL_LIB_CTX_load_config(libctx, NULL);
  //if (strcmp(filter->cipher, "qeep") == 0){}
  if (OSSL_PROVIDER_available(libctx, "qispace_provider"))
        prov = OSSL_PROVIDER_load(libctx, "qispace_provider");
  
  filter->evp_cipher = EVP_get_cipherbyname (filter->cipher);
  if (filter->evp_cipher == NULL )
  { //try using new version 
    filter->evp_cipher = EVP_CIPHER_fetch(libctx, filter->cipher, NULL);
    DEBUG_LOG("EVP_CIPHER_fetch", filter->cipher)
  }

  if (!filter->evp_cipher) {
    GST_ERROR_OBJECT (filter, "Could not get cipher by name from openssl");
    DEBUG_LOG("", "evp_cipher is null")
    return FALSE;
  }
  filter->evp_md = EVP_get_digestbyname ("md5");
  if (!filter->evp_md) {
    GST_ERROR_OBJECT (filter, "Could not get md5 digest by name from openssl");
    return FALSE;
  }
  filter->salt = NULL;
  GST_LOG_OBJECT (filter, "Initialization successfull");
  return TRUE;
}

static GstFlowReturn
gst_crypto_run (GstCrypto * filter)
{
  GstFlowReturn ret = GST_FLOW_OK;
DEBUG_LOG("", "gst_crypto_run")
  EVP_CIPHER_CTX *ctx;
  int len;
  GST_LOG_OBJECT (filter, "Crypto running");

  if (!(ctx = EVP_CIPHER_CTX_new ()))
    return GST_FLOW_ERROR;
// #ifndef AES
//     EVP_CipherInit(ctx, filter->evp_cipher, NULL, NULL, 1);
//     EVP_CIPHER_CTX_set_key_length(ctx, 54);
// #endif
  if (filter->is_encrypting) {
    GST_LOG_OBJECT (filter, "Encrypting");
DEBUG_LOG_HEX("Encrypting plaintext_len", filter->plaintext_len)
    if (1 != EVP_EncryptInit_ex (ctx, filter->evp_cipher, NULL, filter->key,
            filter->iv)) {
      GST_ERROR_OBJECT (filter, "Could not initialize openssl encryption");
      ret = GST_FLOW_ERROR;
      goto crypto_run_out;
    }
    if (1 != EVP_EncryptUpdate (ctx, filter->ciphertext, &len,
            filter->plaintext, filter->plaintext_len)) {
      GST_ERROR_OBJECT (filter, "Could not update openssl encryption");
      ret = GST_FLOW_ERROR;
      goto crypto_run_out;
    }
    filter->ciphertext_len = len;


DEBUG_LOG_HEX("Enc ciphertext len", len)

    if (1 != EVP_EncryptFinal_ex (ctx, filter->ciphertext + len, &len)) {
      GST_ERROR_OBJECT (filter, "Could not finalize openssl encryption");
      ret = GST_FLOW_ERROR;
      goto crypto_run_out;
    }
    filter->ciphertext_len += len;
DEBUG_LOG_HEX("Enc_final ciphertext_len", filter->ciphertext_len)
  } else {
    GST_LOG_OBJECT (filter, "Decrypting");
DEBUG_LOG_HEX("Decrypting ciphertext_len", filter->ciphertext_len)
    if (1 != EVP_DecryptInit_ex (ctx, filter->evp_cipher, NULL, filter->key,
            filter->iv)) {
      GST_ERROR_OBJECT (filter, "Could not initialize openssl decryption");
      ret = GST_FLOW_ERROR;
      goto crypto_run_out;
    }
    if (1 != EVP_DecryptUpdate (ctx, filter->plaintext, &len,
            filter->ciphertext, filter->ciphertext_len)) {
      GST_ERROR_OBJECT (filter, "Could not update openssl decryption");
      ret = GST_FLOW_ERROR;
      goto crypto_run_out;
    }
    filter->plaintext_len = len;
DEBUG_LOG_HEX("Dec plaintext_len", len)
    if (1 != EVP_DecryptFinal_ex (ctx, filter->plaintext + len, &len)) {
      GST_ERROR_OBJECT (filter, "Could not finalize openssl decryption");
      ret = GST_FLOW_ERROR;
      goto crypto_run_out;
    }
DEBUG_LOG_HEX("Dec_final plaintext_len", len)
    filter->plaintext_len += len;
DEBUG_LOG_HEX("Dec_remove plaintext_len", len)
  }
  GST_LOG_OBJECT (filter, "Crypto run successfull");

crypto_run_out:
  EVP_CIPHER_CTX_free (ctx);
  return ret;
}

/* Compute how many bytes have the padding section
 * src_bytes_read: Contain how many bytes are read including padding
 * section, in this variable is returned how many bytes must be read
 * without the padding section.
 */
static void remove_padding(guchar * srcplaintext, gint data_buff_offset, guint * src_bytes_read)
{
  guchar * plaintext;
  guchar padd_value;
  guchar padd_num;
  guchar padd_expected;
  guint bytes_read;

  bytes_read = *src_bytes_read;
  DEBUG_LOG("remove_padding", "enter")
  /* Verify if there is a padding */
  /* Read the number of elements of the padding */
  plaintext = srcplaintext + data_buff_offset + bytes_read - 1;
  padd_value = *(plaintext);
  padd_num = 0;
  padd_expected = padd_value;
  plaintext--;

 /* Verify if the padding is consistent */
  do {
    padd_value = *(plaintext);
    plaintext--;
    padd_num++;
  }
  while (padd_value == padd_expected);

  if (padd_expected != padd_num) {
    GST_INFO ("Padding inconsistent, number: x%X expected x%X",padd_num,padd_expected);
  } else {
    GST_INFO ("Padding consistent, number: x%X expected x%X",padd_num,padd_expected);
    if (1 == padd_expected){
      GST_INFO ("Padding is 1, ignoring it!");
    } else {
      *src_bytes_read = bytes_read - padd_expected;
    }
  }
}

static gboolean
gst_crypto_pass2keyiv (GstCrypto * filter)
{
  GST_LOG_OBJECT (filter, "Coverting pass to key/iv");
  if (strcmp(filter->cipher, "qeep") == 0){
    if (!gst_crypto_hexstring2number (filter, DEFAULT_IV, (gchar *) filter->iv))
      return FALSE;
    if (!gst_crypto_hexstring2number (filter, DEFAULT_KEY, (gchar *) filter->key)) {
      GST_ERROR_OBJECT (filter, "Could not execute QeepKey conversion");
      return FALSE;
    }
  } else {
    if (!EVP_BytesToKey (filter->evp_cipher, filter->evp_md, filter->salt,
            (guchar *) filter->pass, strlen (filter->pass), 1,
            (guchar *) filter->key, (guchar *) filter->iv)) {
      GST_ERROR_OBJECT (filter, "Could not execute openssl key/iv conversion");
      return FALSE;
    }
  }
  GST_LOG_OBJECT (filter, "Key/iv conversion successfull");
  return TRUE;
}

/* General helper functions */
static gboolean
gst_crypto_hexstring2number(GstCrypto * filter, const gchar *in, gchar *out)
{
  gchar byte_val;

  GST_LOG_OBJECT (filter, "Coverting hex string to number");

  if(!in || !out)
    return FALSE;

  while(*in != 0) {
    /* Compute fist half-byte */
    if(*in >= 'A' && *in <= 'F') {
      byte_val = (*in - 55)<<4;
    } else if(*in >= 'a' && *in <= 'f') {
      byte_val = (*in - 87)<<4;
    } else if(*in >= '0' && *in <= '9') {
      byte_val = (*in - 48)<<4;
    } else {
      return FALSE;
    }
    in++;
    if(*in == 0) {
        break;
    }
    /* Compute second half-byte */
    if(*in >= 'A' && *in <= 'F') {
      *out = (*in - 55) + byte_val;
    } else if(*in >= 'a' && *in <= 'f') {
      *out = (*in - 87) + byte_val;
    } else if(*in >= '0' && *in <= '9') {
      *out = (*in - 48) + byte_val;
    } else {
      return FALSE;
    }

    GST_LOG_OBJECT (filter, "ch: %c%c, hex: 0x%x", *(in-1),*in, *out);
    in++; out++;
    if(!in || !out)
      return FALSE;
  }
  GST_LOG_OBJECT (filter, "Hex string conversion successfull");

  return TRUE;
}

/* Object destructor
 */
static void
gst_crypto_finalize (GObject * object)
{
  GstCrypto *filter;

  GST_INFO_OBJECT (filter, "Finalizing");
  filter = GST_CRYPTO (object);

  /* free up used heap */
  if (filter->mode)
    g_free (filter->mode);
  if (filter->cipher)
    g_free (filter->cipher);
  if (filter->pass)
    g_free (filter->pass);
  if (filter->key)
    g_free (filter->key);
  if (filter->iv)
    g_free (filter->iv);
  GST_INFO_OBJECT (filter, "Finalization successfull");
}

/* entry point to initialize the plug-in
 * initialize the plug-in itself
 * register the element factories and other features
 */
static gboolean
crypto_init (GstPlugin * crypto)
{
  return gst_element_register (crypto, "crypto", GST_RANK_NONE,
      GST_TYPE_CRYPTO);
}

/* gstreamer looks for this structure to register crypto element */
GST_PLUGIN_DEFINE (GST_VERSION_MAJOR,
    GST_VERSION_MINOR,
    crypto,
    "crypto encrypt/decrypt element",
    crypto_init, VERSION, "LGPL", "GStreamer", "http://gstreamer.net/")
