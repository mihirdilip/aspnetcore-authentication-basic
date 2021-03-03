// Copyright (c) Mihir Dilip. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

using Xunit;

namespace AspNetCore.Authentication.Basic.Tests
{
    public class BasicDefaultsTests
    {
        [Fact]
        public void AuthenticationSchemeValueTest()
        {
            Assert.Equal("Basic", BasicDefaults.AuthenticationScheme);
        }
    }
}
