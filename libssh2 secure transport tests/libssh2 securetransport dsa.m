//
//  libssh2 securetransport dsa.m
//  libssh2 secure transport
//
//  Created by Keith Duncan on 01/06/2014.
//  Copyright (c) 2014 Keith Duncan. All rights reserved.
//

#import "libssh2test.h"

@interface libssh2_securetransport_dsa : libssh2test

@end

@implementation libssh2_securetransport_dsa

- (void)_testDSASignAndVerifyWithKey:(NSString *)keyName passphrase:(NSString *)passphrase
{
	NSURL *keyLocation = [[NSBundle bundleForClass:self.class] URLForResource:keyName withExtension:nil];

	libssh2_dsa_ctx *key = NULL;
	int dsaError = _libssh2_dsa_new_private(&key, NULL, keyLocation.fileSystemRepresentation, (unsigned char const *)passphrase.UTF8String);
	XCTAssertEqual(dsaError, 0, @"_libssh2_dsa_new_private should return 0");
	if (dsaError != 0) return;

	NSData *data = [self randomData:1024];
	XCTAssertNotNil(data, @"random data should be non nil");
	NSData *sha1 = [self SHA1:data];
	XCTAssertNotNil(sha1, @"sha1(random data) should be non nil");

	size_t signatureLength = SHA_DIGEST_LENGTH;
	unsigned char *signature = malloc(signatureLength);
	dsaError = _libssh2_dsa_sha1_sign(key, [sha1 bytes], [sha1 length], signature);
	XCTAssertEqual(dsaError, 0, @"_libssh2_dsa_sha1_sign should return 0");
	if (dsaError != 0) return;

	dsaError = _libssh2_dsa_sha1_verify(key, signature, [sha1 bytes], [sha1 length]);
	XCTAssertEqual(dsaError, 0, @"_libssh2_dsa_sha1_verify should return 0 for a valid signature");

	NSData *rogueSignature = nil;
	while (rogueSignature == nil || [rogueSignature isEqualToData:[NSData dataWithBytesNoCopy:signature length:signatureLength freeWhenDone:NO]]) {
		rogueSignature = [self randomData:signatureLength];
	}
	[rogueSignature getBytes:signature length:signatureLength];

	dsaError = _libssh2_dsa_sha1_verify(key, signature, [sha1 bytes], [sha1 length]);
	XCTAssertEqual(dsaError, 1, @"_libssh2_dsa_sha1_verify should return 1 for an invalid signature");
	free(signature);

	dsaError = _libssh2_dsa_free(key);
	XCTAssertEqual(dsaError, 0, @"_libssh2_dsa_free should return 0");
}

- (void)test_PKCS8
{
	[self _testDSASignAndVerifyWithKey:@"pkcs8_dsa.p8" passphrase:@"test"];
}

@end
