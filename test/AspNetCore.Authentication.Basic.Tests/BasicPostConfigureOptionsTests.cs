// Copyright (c) Mihir Dilip. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

using AspNetCore.Authentication.Basic.Tests.Infrastructure;
using System;
using System.Threading.Tasks;
using Xunit;

namespace AspNetCore.Authentication.Basic.Tests
{
    public class BasicPostConfigureOptionsTests
    {
		[Fact]
		public async Task PostConfigure_no_option_set_throws_exception()
		{
			await Assert.ThrowsAsync<InvalidOperationException>(() => RunAuthInitAsync(_ => { }));
		}

		[Fact]
		public async Task PostConfigure_Realm_or_SuppressWWWAuthenticateHeader_not_set_throws_exception()
		{
			var exception = await Assert.ThrowsAsync<InvalidOperationException>(() =>
				RunAuthInitWithServiceAsync(_ => { })
			);

			Assert.Contains($"{nameof(BasicOptions.Realm)} must be set in {typeof(BasicOptions).Name} when setting up the authentication.", exception.Message);
		}

		[Fact]
		public async Task PostConfigure_Realm_not_set_but_SuppressWWWAuthenticateHeader_set_no_exception_thrown()
		{
			await RunAuthInitWithServiceAsync(options =>
			{
				options.SuppressWWWAuthenticateHeader = true;
			});
		}

		[Fact]
		public async Task PostConfigure_Realm_set_but_SuppressWWWAuthenticateHeader_not_set_no_exception_thrown()
		{
			await RunAuthInitWithServiceAsync(options =>
			{
				options.Realm = "Test";
			});
		}

		[Fact]
		public async Task PostConfigure_Events_OnValidateKey_or_IBasicProvider_not_set_throws_exception()
		{
			var exception = await Assert.ThrowsAsync<InvalidOperationException>(() =>
				RunAuthInitAsync(options =>
				{
					options.SuppressWWWAuthenticateHeader = true;
				})
			);

			Assert.Contains($"Either {nameof(BasicOptions.Events.OnValidateCredentials)} delegate on configure options {nameof(BasicOptions.Events)} should be set or use an extention method with type parameter of type {nameof(IBasicUserValidationService)}.", exception.Message);
		}

		[Fact]
		public async Task PostConfigure_Events_OnValidateKey_set_but_IBasicProvider_not_set_no_exception_thrown()
		{
			await RunAuthInitAsync(options =>
			{
				options.Events.OnValidateCredentials = _ => Task.CompletedTask;
				options.SuppressWWWAuthenticateHeader = true;
			});
		}

		[Fact]
		public async Task PostConfigure_Events_OnValidateKey_not_set_but_IBasicProvider_set_no_exception_thrown()
		{
			await RunAuthInitWithServiceAsync(options =>
			{
				options.SuppressWWWAuthenticateHeader = true;
			});
		}


		private async Task RunAuthInitAsync(Action<BasicOptions> configureOptions)
		{
			var server = TestServerBuilder.BuildTestServer(configureOptions);
			await server.CreateClient().GetAsync(TestServerBuilder.BaseUrl);
		}

		private async Task RunAuthInitWithServiceAsync(Action<BasicOptions> configureOptions)
		{
			var server = TestServerBuilder.BuildTestServerWithService(configureOptions);
			await server.CreateClient().GetAsync(TestServerBuilder.BaseUrl);
		}
	}
}
