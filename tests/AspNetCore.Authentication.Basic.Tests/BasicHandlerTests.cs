// Copyright (c) Mihir Dilip. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

namespace MadEyeMatt.AspNetCore.Authentication.Basic.Tests
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Net;
    using System.Net.Http;
    using System.Net.Http.Headers;
    using System.Security.Claims;
    using System.Text.Json;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Authentication;
    using Microsoft.AspNetCore.Authorization;
    using Microsoft.AspNetCore.TestHost;
    using Microsoft.Extensions.DependencyInjection;
    using Microsoft.Extensions.Options;
    using Xunit;

    public class BasicHandlerTests : IDisposable
    {
		private const string HeaderFromEventsKey = nameof(HeaderFromEventsKey);
		private const string HeaderFromEventsValue = nameof(HeaderFromEventsValue);

		private readonly TestServer _server;
		private readonly HttpClient _client;
		private readonly TestServer _serverWithService;
		private readonly HttpClient _clientWithService;
		private readonly TestServer _serverWithServiceFactory;
		private readonly HttpClient _clientWithServiceFactory;

		public BasicHandlerTests()
		{
			_server = MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.TestServerBuilder.BuildTestServer();
			_client = _server.CreateClient();

			_serverWithService = MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.TestServerBuilder.BuildTestServerWithService();
			_clientWithService = _serverWithService.CreateClient();

			_serverWithServiceFactory = MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.TestServerBuilder.BuildTestServerWithServiceFactory();
			_clientWithServiceFactory = _serverWithService.CreateClient();
		}

		public void Dispose()
		{
			_client?.Dispose();
			_server?.Dispose();

			_clientWithService?.Dispose();
			_serverWithService?.Dispose();

			_serverWithServiceFactory?.Dispose();
			_clientWithServiceFactory?.Dispose();
		}

		[Fact]
		public async Task Verify_Handler()
		{
			var services = _server.Host.Services;
			var schemeProvider = services.GetRequiredService<IAuthenticationSchemeProvider>();
			Assert.NotNull(schemeProvider);

			var scheme = await schemeProvider.GetDefaultAuthenticateSchemeAsync();
			Assert.NotNull(scheme);
			Assert.Equal(typeof(BasicHandler), scheme.HandlerType);

			var optionsSnapshot = services.GetService<IOptionsSnapshot<BasicOptions>>();
			var options = optionsSnapshot.Get(scheme.Name);
			Assert.NotNull(options);
			Assert.NotNull(options.Events?.OnValidateCredentials);
			Assert.Null(options.BasicUserValidationServiceType);

			var apiKeyProvider = services.GetService<IBasicUserAuthenticationService>();
			Assert.Null(apiKeyProvider);
		}

		[Fact]
		public async Task TBasicUserValidationService_Verify_Handler()
		{
			var services = _serverWithService.Host.Services;
			var schemeProvider = services.GetRequiredService<IAuthenticationSchemeProvider>();
			Assert.NotNull(schemeProvider);

			var scheme = await schemeProvider.GetDefaultAuthenticateSchemeAsync();
			Assert.NotNull(scheme);
			Assert.Equal(typeof(BasicHandler), scheme.HandlerType);

			var optionsSnapshot = services.GetService<IOptionsSnapshot<BasicOptions>>();
			var options = optionsSnapshot.Get(scheme.Name);
			Assert.NotNull(options);
			Assert.Null(options.Events?.OnValidateCredentials);
			Assert.NotNull(options.BasicUserValidationServiceType);
			Assert.Equal(typeof(MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.FakeBasicUserAuthenticationService), options.BasicUserValidationServiceType);

			var apiKeyProvider = services.GetService<IBasicUserAuthenticationService>();
			Assert.NotNull(apiKeyProvider);
			Assert.Equal(typeof(MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.FakeBasicUserAuthenticationService), apiKeyProvider.GetType());
		}

		[Fact]
		public async Task TBasicUserValidationService_Via_Factory_Verify_Handler()
		{
			var services = _serverWithServiceFactory.Host.Services;
			var schemeProvider = services.GetRequiredService<IAuthenticationSchemeProvider>();
			Assert.NotNull(schemeProvider);

			var scheme = await schemeProvider.GetDefaultAuthenticateSchemeAsync();
			Assert.NotNull(scheme);
			Assert.Equal(typeof(BasicHandler), scheme.HandlerType);

			var optionsSnapshot = services.GetService<IOptionsSnapshot<BasicOptions>>();
			var options = optionsSnapshot.Get(scheme.Name);
			Assert.NotNull(options);
			Assert.Null(options.Events?.OnValidateCredentials);
			Assert.Null(options.BasicUserValidationServiceType);

			var basicUserValidationServiceFactory = services.GetService<IBasicUserAuthenticationServiceFactory>();
			Assert.NotNull(basicUserValidationServiceFactory);
		}

		#region HandleForbidden

		[Fact]
		public async Task HandleForbidden()
		{
			using var request = new HttpRequestMessage(HttpMethod.Get, MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.TestServerBuilder.ForbiddenUrl);
			request.Headers.Authorization = MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.FakeUsers.FakeUser.ToAuthenticationHeaderValue();
			using var response = await _clientWithService.SendAsync(request);

			Assert.False(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
			Assert.False(response.Headers.Contains(HeaderFromEventsKey));
		}

		[Fact]
		public async Task HandleForbidden_using_OnHandleForbidden()
		{
			using var server = MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.TestServerBuilder.BuildTestServerWithService(options =>
			{
				options.Realm = MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.TestServerBuilder.Realm;
				options.Events.OnHandleForbidden = context =>
				{
					context.HttpContext.Response.Headers.Add(HeaderFromEventsKey, HeaderFromEventsValue);
					return Task.CompletedTask;
				};
			});
			using var client = server.CreateClient();
			using var request = new HttpRequestMessage(HttpMethod.Get, MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.TestServerBuilder.ForbiddenUrl);
			request.Headers.Authorization = MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.FakeUsers.FakeUser.ToAuthenticationHeaderValue();
			using var response = await client.SendAsync(request);

			Assert.False(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
			Assert.True(response.Headers.Contains(HeaderFromEventsKey));
			Assert.Contains(HeaderFromEventsValue, response.Headers.GetValues(HeaderFromEventsKey));
		}

		#endregion // HandleForbidden

		#region HandleChallenge

		[Fact]
		public async Task HandleChallange()
		{
			using var response = await _clientWithService.GetAsync(MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.TestServerBuilder.BaseUrl);

			Assert.False(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
			Assert.NotEmpty(response.Headers.WwwAuthenticate);
		}

		[Fact]
		public async Task HandleChallange_verify_challenge_www_authenticate_header()
		{
			using var response = await _client.GetAsync(MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.TestServerBuilder.BaseUrl);
			Assert.False(response.IsSuccessStatusCode);

			var wwwAuthenticateHeader = response.Headers.WwwAuthenticate;
			Assert.NotEmpty(wwwAuthenticateHeader);

			var wwwAuthenticateHeaderToMatch = Assert.Single(wwwAuthenticateHeader);
			Assert.NotNull(wwwAuthenticateHeaderToMatch);
			Assert.Equal(BasicDefaults.AuthenticationScheme, wwwAuthenticateHeaderToMatch.Scheme);
			Assert.Equal($"realm=\"{MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.TestServerBuilder.Realm}\", charset=\"UTF-8\"", wwwAuthenticateHeaderToMatch.Parameter);
		}

		[Fact]
		public async Task HandleChallange_using_OnHandleChallenge()
		{
			using var server = MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.TestServerBuilder.BuildTestServerWithService(options =>
			{
				options.Realm = MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.TestServerBuilder.Realm;
				options.Events.OnHandleChallenge = context =>
				{
					context.HttpContext.Response.Headers.Add(HeaderFromEventsKey, HeaderFromEventsValue);
					return Task.CompletedTask;
				};
			});
			using var client = server.CreateClient();
			using var response = await client.GetAsync(MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.TestServerBuilder.BaseUrl);

			Assert.False(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
			Assert.NotEmpty(response.Headers.WwwAuthenticate);
			Assert.True(response.Headers.Contains(HeaderFromEventsKey));
			Assert.Contains(HeaderFromEventsValue, response.Headers.GetValues(HeaderFromEventsKey));
		}

		[Fact]
		public async Task HandleChallange_using_SuppressWWWAuthenticateHeader()
		{
			using var server = MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.TestServerBuilder.BuildTestServerWithService(options =>
			{
				options.Realm = MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.TestServerBuilder.Realm;
				options.SuppressWWWAuthenticateHeader = true;
			});
			using var client = server.CreateClient();
			using var response = await client.GetAsync(MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.TestServerBuilder.BaseUrl);

			Assert.False(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
			Assert.Empty(response.Headers.WwwAuthenticate);
		}

		[Fact]
		public async Task HandleChallange_using_OnHandleChallenge_and_SuppressWWWAuthenticateHeader()
		{
			using var server = MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.TestServerBuilder.BuildTestServerWithService(options =>
			{
				options.Realm = MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.TestServerBuilder.Realm;
				options.SuppressWWWAuthenticateHeader = true;
				options.Events.OnHandleChallenge = context =>
				{
					context.HttpContext.Response.Headers.Add(HeaderFromEventsKey, HeaderFromEventsValue);
					return Task.CompletedTask;
				};
			});
			using var client = server.CreateClient();
			using var response = await client.GetAsync(MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.TestServerBuilder.BaseUrl);

			Assert.False(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
			Assert.Empty(response.Headers.WwwAuthenticate);
			Assert.True(response.Headers.Contains(HeaderFromEventsKey));
			Assert.Contains(HeaderFromEventsValue, response.Headers.GetValues(HeaderFromEventsKey));
		}

		#endregion // HandleChallenge

		#region HandleAuthenticate

		[Fact]
		public async Task HandleAuthenticate_unauthorized()
		{
			using var request = new HttpRequestMessage(HttpMethod.Get, MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.TestServerBuilder.BaseUrl);
			using var response = await _client.SendAsync(request);
			Assert.False(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
		}

		[Fact]
		public async Task HandleAuthenticate_success()
		{
			using var request = new HttpRequestMessage(HttpMethod.Get, MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.TestServerBuilder.BaseUrl);
			request.Headers.Authorization = MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.FakeUsers.FakeUser.ToAuthenticationHeaderValue();
			using var response = await _client.SendAsync(request);
			Assert.True(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.OK, response.StatusCode);
		}

		[Fact]
		public async Task HandleAuthenticate_invalid_scheme_unauthorized()
		{
			using var request = new HttpRequestMessage(HttpMethod.Get, MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.TestServerBuilder.BaseUrl);
			request.Headers.Authorization = new AuthenticationHeaderValue("INVALID", "test");
			using var response = await _client.SendAsync(request);
			Assert.False(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
		}

		[Fact]
		public async Task HandleAuthenticate_invalid_key_unauthorized()
		{
			using var request = new HttpRequestMessage(HttpMethod.Get, MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.TestServerBuilder.BaseUrl);
			request.Headers.Authorization = new AuthenticationHeaderValue(BasicDefaults.AuthenticationScheme, "<invalid>");
			using var response = await _client.SendAsync(request);
			Assert.False(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
		}

		[Fact]
		public async Task HandleAuthenticate_TBasicUserValidationService_Unauthorized()
		{
			using var request = new HttpRequestMessage(HttpMethod.Get, MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.TestServerBuilder.BaseUrl);
			using var response = await _clientWithService.SendAsync(request);
			Assert.False(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
		}

		[Fact]
		public async Task HandleAuthenticate_TBasicUserValidationService_success()
		{
			using var request = new HttpRequestMessage(HttpMethod.Get, MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.TestServerBuilder.BaseUrl);
			request.Headers.Authorization = MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.FakeUsers.FakeUser.ToAuthenticationHeaderValue();
			using var response = await _clientWithService.SendAsync(request);
			Assert.True(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.OK, response.StatusCode);
		}

		[Fact]
		public async Task HandleAuthenticate_TBasicUserValidationService_invalid_scheme_unauthorized()
		{
			using var request = new HttpRequestMessage(HttpMethod.Get, MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.TestServerBuilder.BaseUrl);
			request.Headers.Authorization = new AuthenticationHeaderValue("INVALID", "test");
			using var response = await _clientWithService.SendAsync(request);
			Assert.False(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
		}

		[Fact]
		public async Task HandleAuthenticate_TBasicUserValidationService_invalid_key_unauthorized()
		{
			using var request = new HttpRequestMessage(HttpMethod.Get, MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.TestServerBuilder.BaseUrl);
			request.Headers.Authorization = new AuthenticationHeaderValue(BasicDefaults.AuthenticationScheme, "<invalid>");
			using var response = await _clientWithService.SendAsync(request);
			Assert.False(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
		}

		[Fact]
		public async Task HandleAuthenticate_TBasicUserValidationService_Via_Factory_Unauthorized()
		{
			using var request = new HttpRequestMessage(HttpMethod.Get, MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.TestServerBuilder.BaseUrl);
			using var response = await _clientWithServiceFactory.SendAsync(request);
			Assert.False(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
		}

		[Fact]
		public async Task HandleAuthenticate_TBasicUserValidationService_Via_Factory_success()
		{
			using var request = new HttpRequestMessage(HttpMethod.Get, MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.TestServerBuilder.BaseUrl);
			request.Headers.Authorization = MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.FakeUsers.FakeUser.ToAuthenticationHeaderValue();
			using var response = await _clientWithServiceFactory.SendAsync(request);
			Assert.True(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.OK, response.StatusCode);
		}

		[Fact]
		public async Task HandleAuthenticate_TBasicUserValidationService_Via_Factory_invalid_scheme_unauthorized()
		{
			using var request = new HttpRequestMessage(HttpMethod.Get, MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.TestServerBuilder.BaseUrl);
			request.Headers.Authorization = new AuthenticationHeaderValue("INVALID", "test");
			using var response = await _clientWithServiceFactory.SendAsync(request);
			Assert.False(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
		}

		[Fact]
		public async Task HandleAuthenticate_TBasicUserValidationService_Via_Factory_invalid_key_unauthorized()
		{
			using var request = new HttpRequestMessage(HttpMethod.Get, MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.TestServerBuilder.BaseUrl);
			request.Headers.Authorization = new AuthenticationHeaderValue(BasicDefaults.AuthenticationScheme, "<invalid>");
			using var response = await _clientWithServiceFactory.SendAsync(request);
			Assert.False(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
		}

#if !(NET461 || NETSTANDARD2_0 || NETCOREAPP2_1)

		[Fact]
		public async Task HandleAuthenticate_IgnoreAuthenticationIfAllowAnonymous()
		{
			using var response = await _clientWithService.GetAsync(MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.TestServerBuilder.AnonymousUrl);
			var principal = await DeserializeClaimsPrincipalAsync(response);

			Assert.True(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.OK, response.StatusCode);
			Assert.False(principal.Identity.IsAuthenticated);
		}

#endif

		[Fact]
		public async Task HandleAuthenticate_Password_empty()
		{
			using var request = new HttpRequestMessage(HttpMethod.Get, MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.TestServerBuilder.BaseUrl);
			request.Headers.Authorization = MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.FakeUsers.FakeUserWithEmptyPassword.ToAuthenticationHeaderValue();
			using var response = await _clientWithService.SendAsync(request);

			Assert.True(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.OK, response.StatusCode);
		}

		[Fact]
		public async Task HandleAuthenticate_OnValidateCredentials_result_not_null()
		{
			using var server = MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.TestServerBuilder.BuildTestServerWithService(options =>
			{
				options.Realm = MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.TestServerBuilder.Realm;
				options.Events.OnValidateCredentials = context =>
				{
					context.ValidationSucceeded(new List<Claim> { MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.FakeUsers.FakeRoleClaim, new Claim(ClaimTypes.Name, "my_test") });

					Assert.NotNull(context.Result);

					return Task.CompletedTask;
				};
			});
			using var client = server.CreateClient();
			using var request = new HttpRequestMessage(HttpMethod.Get, MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.TestServerBuilder.ClaimsPrincipalUrl);
			request.Headers.Authorization = MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.FakeUsers.FakeUser.ToAuthenticationHeaderValue();
			using var response = await client.SendAsync(request);
			var principal = await DeserializeClaimsPrincipalAsync(response);

			Assert.True(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.OK, response.StatusCode);
			Assert.Contains(principal.Claims, c => c.Type == MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.FakeUsers.FakeRoleClaim.Type && c.Value == MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.FakeUsers.FakeRoleClaim.Value);
		}

		[Fact]
		public async Task HandleAuthenticate_OnValidateCredentials_result_null()
		{
			using var server = MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.TestServerBuilder.BuildTestServerWithService(options =>
			{
				options.Realm = MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.TestServerBuilder.Realm;
				options.Events.OnValidateCredentials = context =>
				{
					Assert.Null(context.Result);

					return Task.CompletedTask;
				};
			});
			using var client = server.CreateClient();
			using var request = new HttpRequestMessage(HttpMethod.Get, MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.TestServerBuilder.ClaimsPrincipalUrl);
			request.Headers.Authorization = MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.FakeUsers.FakeUser.ToAuthenticationHeaderValue();
			using var response = await client.SendAsync(request);
			var principal = await DeserializeClaimsPrincipalAsync(response);

			Assert.True(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.OK, response.StatusCode);
			Assert.Contains(principal.Claims, c => c.Type == MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.FakeUsers.FakeNameClaim.Type && c.Value == MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.FakeUsers.FakeNameClaim.Value);     // coming from provider, so provider called
		}

		[Fact]
		public async Task HandleAuthenticate_OnValidateCredentials_result_null_without_provider_and_OnAuthenticationFailed_throws()
		{
			var expectedExceptionMessage = $"Either {nameof(MadEyeMatt.AspNetCore.Authentication.Basic.Events.BasicEvents.OnValidateCredentials)} delegate on configure options {nameof(BasicOptions.Events)} should be set or use an extension method with type parameter of type {nameof(IBasicUserAuthenticationService)} or register an implementation of type {nameof(IBasicUserAuthenticationServiceFactory)} in the service collection.";

			using var server = MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.TestServerBuilder.BuildTestServer(options =>
			{
				options.Realm = MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.TestServerBuilder.Realm;
				options.Events.OnValidateCredentials = context =>
				{
					Assert.Null(context.Result);

					return Task.CompletedTask;
				};

				options.Events.OnAuthenticationFailed = context =>
				{
					Assert.NotNull(context.Exception);
					Assert.IsType<InvalidOperationException>(context.Exception);
					Assert.Equal(expectedExceptionMessage, context.Exception.Message);

					return Task.CompletedTask;
				};
			});
			using var client = server.CreateClient();
			using var request = new HttpRequestMessage(HttpMethod.Get, MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.TestServerBuilder.BaseUrl);
			request.Headers.Authorization = MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.FakeUsers.FakeUser.ToAuthenticationHeaderValue();

			var exception = await Assert.ThrowsAsync<InvalidOperationException>(async () =>
			{
				using var response = await client.SendAsync(request);

				Assert.False(response.IsSuccessStatusCode);
				Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
			});

			Assert.Equal(expectedExceptionMessage, exception.Message);
		}

		[Fact]
		public async Task HandleAuthenticate_OnValidateCredentials_result_null_without_provider_and_OnAuthenticationFailed_does_not_throw()
		{
			var expectedExceptionMessage = $"Either {nameof(MadEyeMatt.AspNetCore.Authentication.Basic.Events.BasicEvents.OnValidateCredentials)} delegate on configure options {nameof(BasicOptions.Events)} should be set or use an extension method with type parameter of type {nameof(IBasicUserAuthenticationService)} or register an implementation of type {nameof(IBasicUserAuthenticationServiceFactory)} in the service collection.";

			using var server = MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.TestServerBuilder.BuildTestServer(options =>
			{
				options.Realm = MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.TestServerBuilder.Realm;
				options.Events.OnValidateCredentials = context =>
				{
					Assert.Null(context.Result);

					return Task.CompletedTask;
				};

				options.Events.OnAuthenticationFailed = context =>
				{
					Assert.Null(context.Result);
					Assert.NotNull(context.Exception);
					Assert.IsType<InvalidOperationException>(context.Exception);
					Assert.Equal(expectedExceptionMessage, context.Exception.Message);

					context.NoResult();

					Assert.NotNull(context.Result);

					return Task.CompletedTask;
				};
			});
			using var client = server.CreateClient();
			using var request = new HttpRequestMessage(HttpMethod.Get, MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.TestServerBuilder.BaseUrl);
			request.Headers.Authorization = MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.FakeUsers.FakeUser.ToAuthenticationHeaderValue();
			using var response = await client.SendAsync(request);

			Assert.False(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
		}

		[Fact]
		public async Task HandleAuthenticate_OnAuthenticationSucceeded_result_null()
		{
			using var server = MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.TestServerBuilder.BuildTestServerWithService(options =>
			{
				options.Realm = MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.TestServerBuilder.Realm;
				options.Events.OnAuthenticationSucceeded = context =>
				{
					Assert.Null(context.Result);

					return Task.CompletedTask;
				};
			});
			using var client = server.CreateClient();
			using var request = new HttpRequestMessage(HttpMethod.Get, MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.TestServerBuilder.BaseUrl);
			request.Headers.Authorization = MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.FakeUsers.FakeUser.ToAuthenticationHeaderValue();
			using var response = await client.SendAsync(request);

			Assert.True(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.OK, response.StatusCode);
		}

		[Fact]
		public async Task HandleAuthenticate_OnAuthenticationSucceeded_result_and_principal_null()
		{
			using var server = MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.TestServerBuilder.BuildTestServerWithService(options =>
			{
				options.Realm = MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.TestServerBuilder.Realm;
				options.Events.OnAuthenticationSucceeded = context =>
				{
					context.RejectPrincipal();
					
					Assert.Null(context.Result);
					Assert.Null(context.Principal);

					return Task.CompletedTask;
				};
			});
			using var client = server.CreateClient();
			using var request = new HttpRequestMessage(HttpMethod.Get, MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.TestServerBuilder.BaseUrl);
			request.Headers.Authorization = MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.FakeUsers.FakeUser.ToAuthenticationHeaderValue();
			using var response = await client.SendAsync(request);

			Assert.False(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
		}

		[Fact]
		public async Task HandleAuthenticate_OnAuthenticationSucceeded_result_not_null()
		{
			using var server = MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.TestServerBuilder.BuildTestServerWithService(options =>
			{
				options.Realm = MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.TestServerBuilder.Realm;
				options.Events.OnAuthenticationSucceeded = context =>
				{
					context.Fail("test");

					Assert.NotNull(context.Result);
					Assert.NotNull(context.Principal);

					return Task.CompletedTask;
				};
			});
			using var client = server.CreateClient();
			using var request = new HttpRequestMessage(HttpMethod.Get, MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.TestServerBuilder.BaseUrl);
			request.Headers.Authorization = MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.FakeUsers.FakeUser.ToAuthenticationHeaderValue();
			using var response = await client.SendAsync(request);

			Assert.False(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
		}

        #endregion // HandleAuthenticate

        #region Multi-Scheme

        [Fact]
        public async Task MultiScheme()
        {
            var claimRole = new MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.ClaimDto(MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.FakeUsers.FakeRoleClaim);
			var schemes = new List<string> { "Scheme1", "Scheme2", };

			using var server = MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.TestServerBuilder.BuildTestServer(services =>
            {
                services.AddAuthentication("Scheme1")
                    .AddBasic("Scheme1", options =>
                    {
                        options.Realm = MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.TestServerBuilder.Realm;
                        options.Events.OnValidateCredentials = context =>
                        {
							var user = MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.FakeUsers.Users.FirstOrDefault(u => u.Username.Equals(context.Username, StringComparison.OrdinalIgnoreCase) && u.Password.Equals(context.Password, StringComparison.OrdinalIgnoreCase));
							if (user != null)
							{
								context.Response.Headers.Add("X-Custom", "Scheme1");
								context.ValidationSucceeded(new List<Claim> { MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.FakeUsers.FakeRoleClaim });
							}
                            else
                            {
								context.ValidationFailed();
							}
                            return Task.CompletedTask;
                        };
                    })
                    .AddBasic<FakeBasicUserAuthenticationServiceLocal1>("Scheme2", options =>
                    {
                        options.Realm = MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.TestServerBuilder.Realm;
                    });

#if !(NET461 || NETSTANDARD2_0 || NETCOREAPP2_1)
				services.Configure<AuthorizationOptions>(options => options.FallbackPolicy = new AuthorizationPolicyBuilder(schemes.ToArray()).RequireAuthenticatedUser().Build());
#endif
			});

            using var client = server.CreateClient();

            using var request1 = new HttpRequestMessage(HttpMethod.Get, MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.TestServerBuilder.ClaimsPrincipalUrl + "?scheme=" + schemes[0]);
			request1.Headers.Authorization = MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.FakeUsers.FakeUser.ToAuthenticationHeaderValue();
			using var response1 = await client.SendAsync(request1);
            Assert.True(response1.IsSuccessStatusCode);
            Assert.Equal(HttpStatusCode.OK, response1.StatusCode);
            var response1Principal = await DeserializeClaimsPrincipalAsync(response1);
            Assert.Contains(response1.Headers, r => r.Key == "X-Custom" && r.Value.Any(v => v == "Scheme1"));
            Assert.Contains(response1Principal.Claims, c => c.Type == claimRole.Type && c.Value == claimRole.Value);


            using var request2 = new HttpRequestMessage(HttpMethod.Get, MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.TestServerBuilder.ClaimsPrincipalUrl + "?scheme=" + schemes[1]);
			request2.Headers.Authorization = new MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.User("test", "test").ToAuthenticationHeaderValue();
			using var response2 = await client.SendAsync(request2);
            Assert.True(response2.IsSuccessStatusCode);
            Assert.Equal(HttpStatusCode.OK, response2.StatusCode);
            var response2Principal = await DeserializeClaimsPrincipalAsync(response2);
            Assert.DoesNotContain(response2.Headers, r => r.Key == "X-Custom" && r.Value.Any(v => v == "Scheme1"));
            Assert.DoesNotContain(response2Principal.Claims, c => c.Type == claimRole.Type && c.Value == claimRole.Value);
        }

        #endregion // Multi-Scheme

        private async Task<MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.ClaimsPrincipalDto> DeserializeClaimsPrincipalAsync(HttpResponseMessage response)
        {
			return JsonSerializer.Deserialize<MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.ClaimsPrincipalDto>(await response.Content.ReadAsStringAsync());
		}

        private class FakeBasicUserAuthenticationServiceLocal1 : IBasicUserAuthenticationService
        {
            public Task<IBasicUser> AuthenticateAsync(string username, string password)
            {
				return Task.FromResult((IBasicUser)new MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.FakeBasicUser(username));
            }
        }

		private class FakeBasicUserAuthenticationServiceLocal2 : IBasicUserAuthenticationService
		{
            public Task<IBasicUser> AuthenticateAsync(string username, string password)
            {
				return Task.FromResult((IBasicUser)new MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.FakeBasicUser(username));
			}
		}
	}
}
