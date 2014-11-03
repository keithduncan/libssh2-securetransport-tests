//
//  libssh2test.m
//  libssh2 secure transport
//
//  Created by Keith Duncan on 02/06/2014.
//  Copyright (c) 2014 Keith Duncan. All rights reserved.
//

#import <XCTest/XCTest.h>

#import <CommonCrypto/CommonCrypto.h>

#import "libssh2.h"
#define LIBSSH2_SECURETRANSPORT
#import "crypto.h"
#import "securetransport.h"

@interface libssh2test : XCTestCase

- (NSData *)randomData:(size_t)size;
- (NSData *)SHA1:(NSData *)data;

@end
