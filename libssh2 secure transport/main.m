//
//  main.m
//  libssh2 secure transport
//
//  Created by Keith Duncan on 08/02/2014.
//  Copyright (c) 2014 Keith Duncan. All rights reserved.
//

#import <Foundation/Foundation.h>

#import <CommonCrypto/CommonCrypto.h>

#import "libssh2.h"
#define LIBSSH2_SECURETRANSPORT
#import "crypto.h"
#import "securetransport.h"

#import <Security/cssmerr.h>

static NSData *RandomData(void) {
	uint8_t bytes[1024];
	int error = SecRandomCopyBytes(kSecRandomDefault, sizeof(bytes)/sizeof(*bytes), bytes);
	if (error != 0) return nil;
	return [NSData dataWithBytes:bytes length:sizeof(bytes)/sizeof(*bytes)];
}

static NSData *SHA1(NSData *data) {
	unsigned char hash[CC_SHA1_DIGEST_LENGTH];
	CC_SHA1([data bytes], (CC_LONG)[data length], hash);
	return [NSData dataWithBytes:hash length:sizeof(hash)/sizeof(*hash)];
}

int main(int argc, const char * argv[])
{
	@autoreleasepool {
		libssh2_crypto_init();

        libssh2_rsa_ctx *rsa = NULL;
        int rsaError = _libssh2_rsa_new_private(&rsa, NULL, "/Users/keith/Desktop/libssh2 secure transport/libssh2 secure transport/plain_pkcs1_rsa.pem", NULL);
        NSCParameterAssert(rsaError == 0);

		NSData *data = RandomData();
		NSCParameterAssert(data != nil);
		NSData *sha1 = SHA1(data);
		NSCParameterAssert(sha1 != nil);

		unsigned char *signature = NULL;
		size_t signatureLength = 0;
        rsaError = _libssh2_rsa_sha1_sign(NULL, rsa, [sha1 bytes], [sha1 length], &signature, &signatureLength);
		NSCParameterAssert(rsaError == 0);

		rsaError = _libssh2_rsa_sha1_verify(rsa, signature, signatureLength, [sha1 bytes], [sha1 length]);
		NSCParameterAssert(rsaError == 0);

        rsaError = _libssh2_rsa_free(rsa);
        NSCParameterAssert(rsaError == 0);
	}
    return 0;
}

