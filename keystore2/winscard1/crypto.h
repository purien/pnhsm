/* Copyright (C) 2026 Pascal Urien (pascal.urien@gmail.com)
 * All rights reserved.
 */

#include "param.h"
#ifdef COPENSSL
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h> 
#include <openssl/sha.h>
#include <openssl/ecdsa.h>
#include <openssl/ripemd.h>
#include <openssl/opensslv.h>
#include <openssl/objects.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#else
#include "crypto2.h"
#endif
