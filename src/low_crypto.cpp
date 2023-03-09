// -----------------------------------------------------------------------------
//  low_crypto.cpp
// -----------------------------------------------------------------------------

#include "low_crypto.h"
#include "LowCryptoHash.h"
#include "LowCryptoKeyObject.h"

#include "low_alloc.h"
#include "psa/crypto.h"
#include "mbedtls/base64.h"


// -----------------------------------------------------------------------------
//  low_crypto_create_hash
// -----------------------------------------------------------------------------

duk_ret_t low_crypto_create_hash(duk_context *ctx)
{
    low_t *low = duk_get_low_context(ctx);

    const char *type = duk_require_string(ctx, 1);

    int len = strlen(type);
    char *typeUpper = (char *)low_alloc_throw(ctx, len + 1);
    for(int i = 0; i < len; i++)
        typeUpper[i] = toupper((unsigned)type[i]);
    typeUpper[len] = 0;
    const mbedtls_md_info_t *info = mbedtls_md_info_from_string(typeUpper);
    low_free(typeUpper);

    if(!info)
        duk_reference_error(
          low->duk_ctx, "unsupported hashing algorithm %s!", type);

    unsigned char *key = NULL;
    duk_size_t key_len;
    if(!duk_is_undefined(ctx, 2))
    {
        key = (unsigned char *)duk_get_buffer_data(ctx, 2, &key_len);
        if(!key)
        {
            key = (unsigned char *)duk_require_string(ctx, 2);
            key_len = strlen((char *)key);
        }
    }

    LowCryptoHash *hash = new LowCryptoHash(low, info, key, key_len);

    int index;
    for(index = 0; index < low->cryptoHashes.size(); index++)
        if(!low->cryptoHashes[index])
        {
            low->cryptoHashes[index] = hash;
            break;
        }
    if(index == low->cryptoHashes.size())
        low->cryptoHashes.push_back(hash);
    hash->SetIndex(index);

    duk_push_int(low->duk_ctx, index);
    duk_push_c_function(ctx, low_crypto_hash_finalizer, 1);
    duk_set_finalizer(ctx, 0);

    return 1;
}

// -----------------------------------------------------------------------------
//  low_crypto_hash_finalizer
// -----------------------------------------------------------------------------

duk_ret_t low_crypto_hash_finalizer(duk_context *ctx)
{
    low_t *low = duk_get_low_context(ctx);

    duk_get_prop_string(ctx, 0, "_native");
    int index = duk_require_int(ctx, -1);

    if(index < 0 || index >= low->cryptoHashes.size())
        duk_reference_error(ctx, "crypto hash not found");

    delete low->cryptoHashes[index];
    return 0;
}


// -----------------------------------------------------------------------------
//  low_crypto_hash_update
// -----------------------------------------------------------------------------

duk_ret_t low_crypto_hash_update(duk_context *ctx)
{
    low_t *low = duk_get_low_context(ctx);

    int index = duk_require_int(ctx, 0);
    if(index < 0 || index >= low->cryptoHashes.size())
        duk_reference_error(ctx, "crypto hash not found");

    duk_size_t len;
    void* buffer = duk_require_buffer_data(ctx, 1, &len);

    low->cryptoHashes[index]->Update((unsigned char *)buffer, len);
    return 0;
}


// -----------------------------------------------------------------------------
//  low_crypto_hash_digest
// -----------------------------------------------------------------------------

duk_ret_t low_crypto_hash_digest(duk_context *ctx)
{
    low_t *low = duk_get_low_context(ctx);

    int index = duk_require_int(ctx, 0);
    if(index < 0 || index >= low->cryptoHashes.size())
        duk_reference_error(ctx, "crypto hash not found");

    int len = low->cryptoHashes[index]->OutputSize();
    void* buffer = low_push_buffer(ctx, len);

    low->cryptoHashes[index]->Digest((unsigned char *)buffer, len);
    return 1;
}


// -----------------------------------------------------------------------------
//  low_crypto_random_bytes
// -----------------------------------------------------------------------------

duk_ret_t low_crypto_random_bytes(duk_context *ctx)
{
    int len = duk_require_int(ctx, 0);
    if(!duk_is_undefined(ctx, 1))
        duk_reference_error(ctx, "crypto.randomBytes async version not implemented yet");

    unsigned char *buffer = (unsigned char *)low_push_buffer(ctx, len);
    for(int i = 0; i < len; i++)
        buffer[i] = rand();

    return 1;
}

// -----------------------------------------------------------------------------
//  low_crypto_create_key_object
// -----------------------------------------------------------------------------

int convert_pem_to_der(const unsigned char *input,
                       size_t ilen,
                       unsigned char *output,
                       size_t *olen)
{
    int ret;
    const unsigned char *s1, *s2, *end = input + ilen;
    size_t len = 0;

    s1 = (unsigned char *)strstr((const char *)input, "-----BEGIN");
    if(s1 == NULL)
    {
        return -1;
    }

    s2 = (unsigned char *)strstr((const char *)input, "-----END");
    if(s2 == NULL)
    {
        return -1;
    }

    s1 += 10;
    while(s1 < end && *s1 != '-')
    {
        s1++;
    }
    while(s1 < end && *s1 == '-')
    {
        s1++;
    }
    if(*s1 == '\r')
    {
        s1++;
    }
    if(*s1 == '\n')
    {
        s1++;
    }

    if(s2 <= s1 || s2 > end)
    {
        return -1;
    }

    ret =
      mbedtls_base64_decode(NULL, 0, &len, (const unsigned char *)s1, s2 - s1);
    if(ret == MBEDTLS_ERR_BASE64_INVALID_CHARACTER)
    {
        return ret;
    }

    if(len > *olen)
    {
        return -1;
    }

    if((ret = mbedtls_base64_decode(
          output, len, &len, (const unsigned char *)s1, s2 - s1)) != 0)
    {
        return ret;
    }

    *olen = len;

    return 0;
}

duk_ret_t low_crypto_create_keyobject(duk_context *ctx)
{
    psa_key_id_t key_id;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    low_t *low = duk_get_low_context(ctx);

    /* Initialize PSA Crypto */
    psa_status_t status = psa_crypto_init();
    if(status != PSA_SUCCESS)
    {
        duk_reference_error(ctx, "Failed to initialize PSA Crypto");
    }

    int key_type = duk_require_int(ctx, 1);

    unsigned char *key = NULL;
    duk_size_t key_len;

    key = (unsigned char *)duk_get_buffer_data(ctx, 2, &key_len);
    unsigned char der_buffer[4096];
    if(!key)
    {
        key = (unsigned char *)duk_require_string(ctx, 2);
        key_len = strlen((char *)key);
        int ret;
        duk_size_t der_size = sizeof(der_buffer);
        if((ret = convert_pem_to_der(key, key_len, der_buffer, &der_size)) != 0)
        {
            duk_reference_error(ctx, "convert_pem_to_der failed %d\n\n", ret);
        }
        key = der_buffer;
        key_len = der_size;
    }

    /* Set key attributes */
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_HASH);
    switch(key_type)
    {
        case 1:
            psa_set_key_type(&attributes, PSA_KEY_TYPE_RSA_KEY_PAIR);
            psa_set_key_algorithm(&attributes, PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_ANY_HASH));
            break;
        case 2:
            psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
            psa_set_key_algorithm(&attributes, PSA_ALG_HMAC(PSA_ALG_ANY_HASH));
            break;
        default:
            duk_reference_error(
              ctx, "unsupported key_type constant %d\n\n", key_type);
    }
    psa_set_key_bits(&attributes, 0);

    /* Import the key */
    status = psa_import_key(&attributes, key, key_len, &key_id);
    if(status != PSA_SUCCESS)
    {
        duk_reference_error(ctx, "Failed to import key: %d", status);
    }

    LowCryptoKeyObject *keyObject = new LowCryptoKeyObject(low, key_id);
    /* Free the attributes */
    psa_reset_key_attributes(&attributes);

    int index;
    for(index = 0; index < low->cryptoKeyObjects.size(); index++)
        if(!low->cryptoKeyObjects[index])
        {
            low->cryptoKeyObjects[index] = keyObject;
            break;
        }
    if(index == low->cryptoKeyObjects.size())
        low->cryptoKeyObjects.push_back(keyObject);
    keyObject->SetIndex(index);

    duk_push_int(low->duk_ctx, index);
    duk_push_c_function(ctx, low_crypto_keyobject_finalizer, 1);
    duk_set_finalizer(ctx, 0);

    return 1;
}


// -----------------------------------------------------------------------------
//  low_crypto_keyobject_finalizer
// -----------------------------------------------------------------------------

duk_ret_t low_crypto_keyobject_finalizer(duk_context *ctx)
{
    low_t *low = duk_get_low_context(ctx);

    duk_get_prop_string(ctx, 0, "_native");
    int index = duk_require_int(ctx, -1);

    if(index < 0 || index >= low->cryptoKeyObjects.size())
        duk_reference_error(ctx, "crypto keyobject not found");

    delete low->cryptoKeyObjects[index];
    return 0;
}


// -----------------------------------------------------------------------------
//  low_crypto_sign
// -----------------------------------------------------------------------------
duk_ret_t low_crypto_sign(duk_context *ctx)
{
    low_t *low = duk_get_low_context(ctx);

    int keyIndex = duk_require_int(ctx, 0);

    uint8_t *hash = NULL;
    duk_size_t hash_len;

    hash = (uint8_t *)duk_get_buffer_data(ctx, 1, &hash_len);

    uint8_t signature[PSA_SIGNATURE_MAX_SIZE] = {0};
    size_t signature_length;

    if(keyIndex < 0 || keyIndex >= low->cryptoKeyObjects.size())
        duk_reference_error(ctx, "crypto keyobject not found");

    psa_algorithm_t hashAlgorithm;
    const char *hashType = duk_require_string(ctx, 2);

    if(!strcasecmp("SHA1", hashType))
    {
        hashAlgorithm = PSA_ALG_SHA_1;
    }
    else if(!strcasecmp("SHA224", hashType))
    {
        hashAlgorithm = PSA_ALG_SHA_224;
    }
    else if(!strcasecmp("SHA256", hashType))
    {
        hashAlgorithm = PSA_ALG_SHA_256;
    }
    else if(!strcasecmp("SHA384", hashType))
    {
        hashAlgorithm = PSA_ALG_SHA_384;
    }
    else if(!strcasecmp("SHA512", hashType))
    {
        hashAlgorithm = PSA_ALG_SHA_512;
    }
    else if(!strcasecmp("MD5", hashType))
    {
        hashAlgorithm = PSA_ALG_MD5;
    }
    else
    {
        duk_reference_error(ctx, "Unknown hash algorithm %s", hashType);
    }


    /* Sign message using the key */
    psa_status_t status = psa_sign_hash(
      low->cryptoKeyObjects[keyIndex]->mKeyId,
      PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_256), // TODO: Make alg configurable
      hash,
      hash_len,
      signature,
      sizeof(signature),
      &signature_length);
    if(status != PSA_SUCCESS)
    {
        duk_reference_error(ctx, "Failed to sign: %d\n", status);
    }

    void *buffer = low_push_buffer(ctx, signature_length);
    memcpy(buffer, signature, signature_length);

    return 1;
}
