//
//  libssh2 securetransport rsa.m
//  libssh2 secure transport
//
//  Created by Keith Duncan on 23/02/2014.
//  Copyright (c) 2014 Keith Duncan. All rights reserved.
//

#import "libssh2test.h"

@interface libssh2_securetransport_rsa : libssh2test

@end

@implementation libssh2_securetransport_rsa

- (void)_testRSASignAndVerifyWithKey:(NSString *)keyName passphrase:(NSString *)passphrase
{
	NSURL *keyLocation = [[NSBundle bundleForClass:self.class] URLForResource:keyName withExtension:nil];

	libssh2_rsa_ctx *rsa = NULL;
	int rsaError = _libssh2_rsa_new_private(&rsa, NULL, keyLocation.fileSystemRepresentation, (unsigned char const *)passphrase.UTF8String);
	XCTAssertEqual(rsaError, 0, @"_libssh2_rsa_new_private should return 0");
	if (rsaError != 0) return;

	NSData *data = [self randomData:1024];
	XCTAssertNotNil(data, @"random data should be non nil");
	NSData *sha1 = [self SHA1:data];
	XCTAssertNotNil(sha1, @"sha1(random data) should be non nil");

	unsigned char *signature = NULL;
	size_t signatureLength = 0;
	rsaError = _libssh2_rsa_sha1_sign(NULL, rsa, [sha1 bytes], [sha1 length], &signature, &signatureLength);
	XCTAssertEqual(rsaError, 0, @"_libssh2_rsa_sha1_sign should return 0");
	if (rsaError != 0) return;

	rsaError = _libssh2_rsa_sha1_verify(rsa, signature, signatureLength, [sha1 bytes], [sha1 length]);
	XCTAssertEqual(rsaError, 0, @"_libssh2_rsa_sha1_verify should return 0 for a valid signature");

	NSData *rogueSignature = nil;
	while (rogueSignature == nil || [rogueSignature isEqualToData:[NSData dataWithBytesNoCopy:signature length:signatureLength freeWhenDone:NO]]) {
		rogueSignature = [self randomData:signatureLength];
	}
	[rogueSignature getBytes:signature length:signatureLength];

	rsaError = _libssh2_rsa_sha1_verify(rsa, signature, signatureLength, [sha1 bytes], [sha1 length]);
	XCTAssertEqual(rsaError, 1, @"_libssh2_rsa_sha1_verify should return 1 for an invalid signature");
	free(signature);

	rsaError = _libssh2_rsa_free(rsa);
	XCTAssertEqual(rsaError, 0, @"_libssh2_rsa_free should return 0");
}

#warning test that keys created using _libssh2_rsa_new can be used for sign verify

- (void)test_PEM_PKCS1_Plain
{
	[self _testRSASignAndVerifyWithKey:@"plain_pkcs1_rsa.pem" passphrase:nil];
}

- (void)test_PEM_PKCS8_Plain
{
	[self _testRSASignAndVerifyWithKey:@"plain_pkcs8_rsa.pem" passphrase:nil];
}

- (void)test_DER_PKCS8_Plain
{
	[self _testRSASignAndVerifyWithKey:@"plain_pkcs8_rsa.p8" passphrase:nil];
}

- (void)test_PEM_PKCS1_Cipher
{
	[self _testRSASignAndVerifyWithKey:@"enc_pkcs1_rsa.pem" passphrase:@"test"];
}

- (void)test_PEM_PKCS8_Cipher
{
	[self _testRSASignAndVerifyWithKey:@"enc_pkcs8_rsa.pem" passphrase:@"test"];
}

- (void)test_DER_PKCS8_Cipher
{
	[self _testRSASignAndVerifyWithKey:@"enc_pkcs8_rsa.p8" passphrase:@"test"];
}

@end
