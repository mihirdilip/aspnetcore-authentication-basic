// Copyright (c) Mihir Dilip. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

namespace MadEyeMatt.AspNetCore.Authentication.Basic.Tests
{
    using System;
    using System.Threading.Tasks;
    using Xunit;

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

			Assert.Contains($"{nameof(BasicOptions.Realm)} must be set in {nameof(BasicOptions)} when setting up the authentication.", exception.Message);
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
		public async Task PostConfigure_Events_OnValidateKey_or_IBasicUserValidationService_or_IBasicUserValidationServiceFactory_not_set_throws_exception()
		{
			var exception = await Assert.ThrowsAsync<InvalidOperationException>(() =>
				RunAuthInitAsync(options =>
				{
					options.SuppressWWWAuthenticateHeader = true;
				})
			);

			Assert.Contains($"Either {nameof(BasicOptions.Events.OnValidateCredentials)} delegate on configure options {nameof(BasicOptions.Events)} should be set or use an extension method with type parameter of type {nameof(IBasicUserAuthenticationService)} or register an implementation of type {nameof(IBasicUserAuthenticationServiceFactory)} in the service collection.", exception.Message);
		}

		[Fact]
		public async Task PostConfigure_Events_OnValidateKey_set_but_IBasicUserValidationService_not_set_no_exception_thrown()
		{
			await RunAuthInitAsync(options =>
			{
				options.Events.OnValidateCredentials = _ => Task.CompletedTask;
				options.SuppressWWWAuthenticateHeader = true;
			});
		}

		[Fact]
		public async Task PostConfigure_Events_OnValidateKey_not_set_but_IBasicUserValidationService_set_no_exception_thrown()
		{
			await RunAuthInitWithServiceAsync(options =>
			{
				options.SuppressWWWAuthenticateHeader = true;
			});
		}

		[Fact]
		public async Task PostConfigure_Events_OnValidateKey_not_set_and_IBasicUserValidationService_not_set_but_IBasicUserValidationServiceFactory_registered_no_exception_thrown()
		{
			await RunAuthInitWithServiceFactoryAsync(options =>
			{
				options.SuppressWWWAuthenticateHeader = true;
			});
		}

		private async Task RunAuthInitAsync(Action<BasicOptions> configureOptions)
		{
			var server = MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.TestServerBuilder.BuildTestServer(configureOptions);
			await server.CreateClient().GetAsync(MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.TestServerBuilder.BaseUrl);
		}

		private async Task RunAuthInitWithServiceAsync(Action<BasicOptions> configureOptions)
		{
			var server = MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.TestServerBuilder.BuildTestServerWithService(configureOptions);
			await server.CreateClient().GetAsync(MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.TestServerBuilder.BaseUrl);
		}

		private async Task RunAuthInitWithServiceFactoryAsync(Action<BasicOptions> configureOptions)
		{
			var server = MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.TestServerBuilder.BuildTestServerWithServiceFactory(configureOptions);
			await server.CreateClient().GetAsync(MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.TestServerBuilder.BaseUrl);
		}
	}
}
