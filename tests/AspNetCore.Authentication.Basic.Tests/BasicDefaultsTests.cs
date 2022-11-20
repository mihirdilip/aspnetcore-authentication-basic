// Copyright (c) Mihir Dilip. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

namespace MadEyeMatt.AspNetCore.Authentication.Basic.Tests
{
	using Xunit;

	public class BasicDefaultsTests
	{
		[Fact]
		public void AuthenticationSchemeValueTest()
		{
			Assert.Equal("Basic", BasicDefaults.AuthenticationScheme);
		}
	}
}
