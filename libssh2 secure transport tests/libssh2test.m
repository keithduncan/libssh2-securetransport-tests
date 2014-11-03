//
//  libssh2test.m
//  libssh2 secure transport
//
//  Created by Keith Duncan on 02/06/2014.
//  Copyright (c) 2014 Keith Duncan. All rights reserved.
//

#import "libssh2test.h"

@implementation libssh2test

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

- (NSData *)randomData:(size_t)size {
	NSMutableData *data = [NSMutableData dataWithLength:size];
	int error = SecRandomCopyBytes(kSecRandomDefault, size, [data mutableBytes]);
	if (error != 0) return nil;
	return data;
}

- (NSData *)SHA1:(NSData *)data {
	unsigned char hash[CC_SHA1_DIGEST_LENGTH];
	CC_SHA1([data bytes], (CC_LONG)[data length], hash);
	return [NSData dataWithBytes:hash length:sizeof(hash)/sizeof(*hash)];
}

@end
