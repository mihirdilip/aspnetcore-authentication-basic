// Copyright (c) Mihir Dilip. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

namespace MadEyeMatt.AspNetCore.Authentication.Basic.Tests
{
	using System;
	using System.Net;
	using System.Net.Http;
	using System.Net.Http.Headers;
	using System.Threading.Tasks;
	using Microsoft.AspNetCore.TestHost;
	using Microsoft.Extensions.DependencyInjection;
	using Microsoft.Extensions.Options;
	using Xunit;

	public class BasicOptionsTests
	{
		[Fact]
		public void BasicUserValidationServiceType_default_null()
		{
			BasicOptions options = new BasicOptions();
			Assert.Null(options.BasicUserValidationServiceType);
		}

		[Fact]
		public void BasicUserValidationServiceType_verify_not_null()
		{
			using TestServer server = MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.TestServerBuilder.BuildTestServerWithService();
			IServiceProvider services = server.Host.Services;

			IOptionsSnapshot<BasicOptions> apiKeyOptionsSnapshot = services.GetService<IOptionsSnapshot<BasicOptions>>();
			BasicOptions apiKeyOptions = apiKeyOptionsSnapshot.Get(BasicDefaults.AuthenticationScheme);
			Assert.NotNull(apiKeyOptions);
			Assert.NotNull(apiKeyOptions.BasicUserValidationServiceType);
			Assert.Equal(typeof(MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.FakeBasicUserAuthenticationService), apiKeyOptions.BasicUserValidationServiceType);

			IBasicUserAuthenticationService apiKeyProvider = services.GetService<IBasicUserAuthenticationService>();
			Assert.NotNull(apiKeyProvider);
			Assert.Equal(typeof(MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.FakeBasicUserAuthenticationService), apiKeyProvider.GetType());
		}

		[Fact]
		public void BasicUserValidationServiceType_verify_null()
		{
			using TestServer server = MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.TestServerBuilder.BuildTestServer();
			IServiceProvider services = server.Host.Services;

			IOptionsSnapshot<BasicOptions> apiKeyOptionsSnapshot = services.GetService<IOptionsSnapshot<BasicOptions>>();
			BasicOptions apiKeyOptions = apiKeyOptionsSnapshot.Get(BasicDefaults.AuthenticationScheme);
			Assert.NotNull(apiKeyOptions);
			Assert.Null(apiKeyOptions.BasicUserValidationServiceType);

			IBasicUserAuthenticationService apiKeyProvider = services.GetService<IBasicUserAuthenticationService>();
			Assert.Null(apiKeyProvider);
		}

		[Fact]
		public void Events_default_not_null()
		{
			BasicOptions options = new BasicOptions();
			Assert.NotNull(options.Events);
		}

		[Fact]
		public void SuppressWWWAuthenticateHeader_default_false()
		{
			BasicOptions options = new BasicOptions();
			Assert.False(options.SuppressWWWAuthenticateHeader);
		}

		[Fact]
		public async Task SuppressWWWAuthenticateHeader_verify_false()
		{
			string realm = MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.TestServerBuilder.Realm;
			using TestServer server = MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.TestServerBuilder.BuildTestServerWithService(options =>
			{
				options.Realm = realm;
				options.SuppressWWWAuthenticateHeader = false;
			});

			using HttpClient client = server.CreateClient();
			using HttpResponseMessage response = await client.GetAsync(MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.TestServerBuilder.BaseUrl);

			Assert.False(response.IsSuccessStatusCode);

			HttpHeaderValueCollection<AuthenticationHeaderValue> wwwAuthenticateHeader = response.Headers.WwwAuthenticate;
			Assert.NotEmpty(wwwAuthenticateHeader);

			AuthenticationHeaderValue wwwAuthenticateHeaderToMatch = Assert.Single(wwwAuthenticateHeader);
			Assert.NotNull(wwwAuthenticateHeaderToMatch);
			Assert.Equal(BasicDefaults.AuthenticationScheme, wwwAuthenticateHeaderToMatch.Scheme);
			Assert.Equal($"realm=\"{realm}\", charset=\"UTF-8\"", wwwAuthenticateHeaderToMatch.Parameter);
		}

		[Fact]
		public async Task SuppressWWWAuthenticateHeader_verify_true()
		{
			string realm = MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.TestServerBuilder.Realm;
			using TestServer server = MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.TestServerBuilder.BuildTestServerWithService(options =>
			{
				options.Realm = realm;
				options.SuppressWWWAuthenticateHeader = true;
			});

			using HttpClient client = server.CreateClient();
			using HttpResponseMessage response = await client.GetAsync(MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.TestServerBuilder.BaseUrl);

			Assert.False(response.IsSuccessStatusCode);
			Assert.Empty(response.Headers.WwwAuthenticate);
		}

#if !(NET461 || NETSTANDARD2_0 || NETCOREAPP2_1)

		[Fact]
		public void IgnoreAuthenticationIfAllowAnonymous_default_false()
		{
			BasicOptions options = new BasicOptions();
			Assert.False(options.IgnoreAuthenticationIfAllowAnonymous);
		}

		[Fact]
		public async Task IgnoreAuthenticationIfAllowAnonymous_verify_false()
		{
			string realm = MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.TestServerBuilder.Realm;
			using TestServer server = MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.TestServerBuilder.BuildTestServerWithService(options =>
			{
				options.Realm = realm;
				options.IgnoreAuthenticationIfAllowAnonymous = false;
			});

			using HttpClient client = server.CreateClient();
			using HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.TestServerBuilder.AnonymousUrl);
			request.Headers.Authorization = MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.FakeUsers.FakeUserIgnoreAuthenticationIfAllowAnonymous.ToAuthenticationHeaderValue();

			InvalidOperationException exception = await Assert.ThrowsAsync<InvalidOperationException>(() => client.SendAsync(request));

			Assert.Equal(nameof(BasicOptions.IgnoreAuthenticationIfAllowAnonymous), exception.Message);
		}

		[Fact]
		public async Task IgnoreAuthenticationIfAllowAnonymous_verify_true()
		{
			string realm = MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.TestServerBuilder.Realm;
			using TestServer server = MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.TestServerBuilder.BuildTestServerWithService(options =>
			{
				options.Realm = realm;
				options.IgnoreAuthenticationIfAllowAnonymous = true;
			});

			using HttpClient client = server.CreateClient();
			using HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.TestServerBuilder.AnonymousUrl);
			request.Headers.Authorization = MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.FakeUsers.FakeUserIgnoreAuthenticationIfAllowAnonymous.ToAuthenticationHeaderValue();
			using HttpResponseMessage response = await client.SendAsync(request);

			Assert.True(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.OK, response.StatusCode);
		}

#endif
	}
}
