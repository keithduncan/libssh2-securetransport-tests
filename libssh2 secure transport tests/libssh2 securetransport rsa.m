//
//  libssh2 securetransport rsa.m
//  libssh2 secure transport
//
//  Created by Keith Duncan on 23/02/2014.
//  Copyright (c) 2014 Keith Duncan. All rights reserved.
//

#import <XCTest/XCTest.h>

#import <CommonCrypto/CommonCrypto.h>

#import "libssh2.h"
#define LIBSSH2_SECURETRANSPORT
#import "crypto.h"
#import "securetransport.h"

@interface libssh2_securetransport_rsa : XCTestCase

@end

static NSData *RandomData(size_t size) {
	uint8_t bytes[size];
	int error = SecRandomCopyBytes(kSecRandomDefault, sizeof(bytes)/sizeof(*bytes), bytes);
	if (error != 0) return nil;
	return [NSData dataWithBytes:bytes length:sizeof(bytes)/sizeof(*bytes)];
}

static NSData *SHA1(NSData *data) {
	unsigned char hash[CC_SHA1_DIGEST_LENGTH];
	CC_SHA1([data bytes], (CC_LONG)[data length], hash);
	return [NSData dataWithBytes:hash length:sizeof(hash)/sizeof(*hash)];
}

@implementation libssh2_securetransport_rsa

- (void)setUp
{
	[super setUp];

	libssh2_crypto_init();
}

- (void)tearDown
{
	[super tearDown];

	libssh2_crypto_exit();
}

- (void)_testRSASignAndVerifyWithKey:(NSURL *)keyLocation passphrase:(NSString *)passphrase
{
	libssh2_rsa_ctx *rsa = NULL;
	int rsaError = _libssh2_rsa_new_private(&rsa, NULL, keyLocation.fileSystemRepresentation, (unsigned char const *)passphrase.UTF8String);
	XCTAssertEqual(rsaError, 0, @"_libssh2_rsa_new_private should return 0");

	NSData *data = RandomData(1024);
	XCTAssertNotNil(data, @"random data should be non nil");
	NSData *sha1 = SHA1(data);
	XCTAssertNotNil(sha1, @"sha1(random data) should be non nil");

	unsigned char *signature = NULL;
	size_t signatureLength = 0;
	rsaError = _libssh2_rsa_sha1_sign(NULL, rsa, [sha1 bytes], [sha1 length], &signature, &signatureLength);
	XCTAssertEqual(rsaError, 0, @"_libssh2_rsa_sha1_sign should return 0");

	rsaError = _libssh2_rsa_sha1_verify(rsa, signature, signatureLength, [sha1 bytes], [sha1 length]);
	XCTAssertEqual(rsaError, 0, @"_libssh2_rsa_sha1_verify should return 0 for a valid signature");

	NSData *rogueSignature = nil;
	while (rogueSignature == nil || [rogueSignature isEqualToData:[NSData dataWithBytesNoCopy:signature length:signatureLength freeWhenDone:NO]]) {
		rogueSignature = RandomData(signatureLength);
	}
	[rogueSignature getBytes:signature length:signatureLength];

	rsaError = _libssh2_rsa_sha1_verify(rsa, signature, signatureLength, [sha1 bytes], [sha1 length]);
	XCTAssertEqual(rsaError, 1, @"_libssh2_rsa_sha1_verify should return 1 for an invalid signature");
	free(signature);

	rsaError = _libssh2_rsa_free(rsa);
	XCTAssertEqual(rsaError, 0, @"_libssh2_rsa_free should return 0");
}

- (void)test_PEM_PKCS1_Plain
{
	[self _testRSASignAndVerifyWithKey:[[NSBundle bundleForClass:self.class] URLForResource:@"plain_pkcs1_rsa" withExtension:@"pem"] passphrase:nil];
}

- (void)test_PEM_PKCS8_Plain
{
	[self _testRSASignAndVerifyWithKey:[[NSBundle bundleForClass:self.class] URLForResource:@"plain_pkcs8_rsa" withExtension:@"pem"] passphrase:nil];
}

- (void)test_DER_PKCS8_Plain
{
	[self _testRSASignAndVerifyWithKey:[[NSBundle bundleForClass:self.class] URLForResource:@"plain_pkcs8_rsa" withExtension:@"der"] passphrase:nil];
}

@end
