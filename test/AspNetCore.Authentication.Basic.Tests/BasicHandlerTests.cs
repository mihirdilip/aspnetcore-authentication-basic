// Copyright (c) Mihir Dilip. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

using AspNetCore.Authentication.Basic.Tests.Infrastructure;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text.Json;
using System.Threading.Tasks;
using Xunit;

namespace AspNetCore.Authentication.Basic.Tests
{
	public class BasicHandlerTests : IDisposable
	{
		private const string HeaderFromEventsKey = nameof(HeaderFromEventsKey);
		private const string HeaderFromEventsValue = nameof(HeaderFromEventsValue);

		private readonly TestServer _server;
		private readonly HttpClient _client;
		private readonly TestServer _serverWithService;
		private readonly HttpClient _clientWithService;

		public BasicHandlerTests()
		{
			_server = TestServerBuilder.BuildTestServer();
			_client = _server.CreateClient();

			_serverWithService = TestServerBuilder.BuildTestServerWithService();
			_clientWithService = _serverWithService.CreateClient();
		}

		public void Dispose()
		{
			_client?.Dispose();
			_server?.Dispose();

			_clientWithService?.Dispose();
			_serverWithService?.Dispose();
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
			var options = optionsSnapshot?.Get(scheme.Name);
			Assert.NotNull(options);
			Assert.NotNull(options.Events?.OnValidateCredentials);
			Assert.Null(options.BasicUserValidationServiceType);

			var apiKeyProvider = services.GetService<IBasicUserValidationService>();
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
			var options = optionsSnapshot?.Get(scheme.Name);
			Assert.NotNull(options);
			Assert.Null(options.Events?.OnValidateCredentials);
			Assert.NotNull(options.BasicUserValidationServiceType);
			Assert.Equal(typeof(FakeBasicUserValidationService), options.BasicUserValidationServiceType);

			var apiKeyProvider = services.GetService<IBasicUserValidationService>();
			Assert.NotNull(apiKeyProvider);
			Assert.Equal(typeof(FakeBasicUserValidationService), apiKeyProvider.GetType());
		}

		#region HandleForbidden

		[Fact]
		public async Task HandleForbidden()
		{
			using var request = new HttpRequestMessage(HttpMethod.Get, TestServerBuilder.ForbiddenUrl);
			request.Headers.Authorization = FakeUsers.FakeUser.ToAuthenticationHeaderValue();
			using var response = await _clientWithService.SendAsync(request);

			Assert.False(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
			Assert.False(response.Headers.Contains(HeaderFromEventsKey));
		}

		[Fact]
		public async Task HandleForbidden_using_OnHandleForbidden()
		{
			using var server = TestServerBuilder.BuildTestServerWithService(options =>
			{
				options.Realm = TestServerBuilder.Realm;
				options.Events.OnHandleForbidden = context =>
				{
					context.HttpContext.Response.Headers[HeaderFromEventsKey] = HeaderFromEventsValue;
					return Task.CompletedTask;
				};
			});
			using var client = server.CreateClient();
			using var request = new HttpRequestMessage(HttpMethod.Get, TestServerBuilder.ForbiddenUrl);
			request.Headers.Authorization = FakeUsers.FakeUser.ToAuthenticationHeaderValue();
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
			using var response = await _clientWithService.GetAsync(TestServerBuilder.BaseUrl);

			Assert.False(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
			Assert.NotEmpty(response.Headers.WwwAuthenticate);
		}

		[Fact]
		public async Task HandleChallange_verify_challenge_www_authenticate_header()
		{
			using var response = await _client.GetAsync(TestServerBuilder.BaseUrl);
			Assert.False(response.IsSuccessStatusCode);

			var wwwAuthenticateHeader = response.Headers.WwwAuthenticate;
			Assert.NotEmpty(wwwAuthenticateHeader);

			var wwwAuthenticateHeaderToMatch = Assert.Single(wwwAuthenticateHeader);
			Assert.NotNull(wwwAuthenticateHeaderToMatch);
			Assert.Equal(BasicDefaults.AuthenticationScheme, wwwAuthenticateHeaderToMatch.Scheme);
			Assert.Equal($"realm=\"{TestServerBuilder.Realm}\", charset=\"UTF-8\"", wwwAuthenticateHeaderToMatch.Parameter);
		}

		[Fact]
		public async Task HandleChallange_using_OnHandleChallenge()
		{
			using var server = TestServerBuilder.BuildTestServerWithService(options =>
			{
				options.Realm = TestServerBuilder.Realm;
				options.Events.OnHandleChallenge = context =>
				{
					context.HttpContext.Response.Headers[HeaderFromEventsKey] = HeaderFromEventsValue;
					return Task.CompletedTask;
				};
			});
			using var client = server.CreateClient();
			using var response = await client.GetAsync(TestServerBuilder.BaseUrl);

			Assert.False(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
			Assert.NotEmpty(response.Headers.WwwAuthenticate);
			Assert.True(response.Headers.Contains(HeaderFromEventsKey));
			Assert.Contains(HeaderFromEventsValue, response.Headers.GetValues(HeaderFromEventsKey));
		}

		[Fact]
		public async Task HandleChallange_using_SuppressWWWAuthenticateHeader()
		{
			using var server = TestServerBuilder.BuildTestServerWithService(options =>
			{
				options.Realm = TestServerBuilder.Realm;
				options.SuppressWWWAuthenticateHeader = true;
			});
			using var client = server.CreateClient();
			using var response = await client.GetAsync(TestServerBuilder.BaseUrl);

			Assert.False(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
			Assert.Empty(response.Headers.WwwAuthenticate);
		}

		[Fact]
		public async Task HandleChallange_using_OnHandleChallenge_and_SuppressWWWAuthenticateHeader()
		{
			using var server = TestServerBuilder.BuildTestServerWithService(options =>
			{
				options.Realm = TestServerBuilder.Realm;
				options.SuppressWWWAuthenticateHeader = true;
				options.Events.OnHandleChallenge = context =>
				{
					context.HttpContext.Response.Headers[HeaderFromEventsKey] = HeaderFromEventsValue;
					return Task.CompletedTask;
				};
			});
			using var client = server.CreateClient();
			using var response = await client.GetAsync(TestServerBuilder.BaseUrl);

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
			using var request = new HttpRequestMessage(HttpMethod.Get, TestServerBuilder.BaseUrl);
			using var response = await _client.SendAsync(request);
			Assert.False(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
		}

		[Fact]
		public async Task HandleAuthenticate_success()
		{
			using var request = new HttpRequestMessage(HttpMethod.Get, TestServerBuilder.BaseUrl);
			request.Headers.Authorization = FakeUsers.FakeUser.ToAuthenticationHeaderValue();
			using var response = await _client.SendAsync(request);
			Assert.True(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.OK, response.StatusCode);
		}

		[Fact]
		public async Task HandleAuthenticate_invalid_scheme_unauthorized()
		{
			using var request = new HttpRequestMessage(HttpMethod.Get, TestServerBuilder.BaseUrl);
			request.Headers.Authorization = new AuthenticationHeaderValue("INVALID", "test");
			using var response = await _client.SendAsync(request);
			Assert.False(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
		}

		[Fact]
		public async Task HandleAuthenticate_invalid_key_unauthorized()
		{
			using var request = new HttpRequestMessage(HttpMethod.Get, TestServerBuilder.BaseUrl);
			request.Headers.Authorization = new AuthenticationHeaderValue(BasicDefaults.AuthenticationScheme, "<invalid>");
			using var response = await _client.SendAsync(request);
			Assert.False(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
		}

		[Fact]
		public async Task HandleAuthenticate_TBasicUserValidationService_Unauthorized()
		{
			using var request = new HttpRequestMessage(HttpMethod.Get, TestServerBuilder.BaseUrl);
			using var response = await _clientWithService.SendAsync(request);
			Assert.False(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
		}

		[Fact]
		public async Task HandleAuthenticate_TBasicUserValidationService_success()
		{
			using var request = new HttpRequestMessage(HttpMethod.Get, TestServerBuilder.BaseUrl);
			request.Headers.Authorization = FakeUsers.FakeUser.ToAuthenticationHeaderValue();
			using var response = await _clientWithService.SendAsync(request);
			Assert.True(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.OK, response.StatusCode);
		}

		[Fact]
		public async Task HandleAuthenticate_TBasicUserValidationService_invalid_scheme_unauthorized()
		{
			using var request = new HttpRequestMessage(HttpMethod.Get, TestServerBuilder.BaseUrl);
			request.Headers.Authorization = new AuthenticationHeaderValue("INVALID", "test");
			using var response = await _clientWithService.SendAsync(request);
			Assert.False(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
		}

		[Fact]
		public async Task HandleAuthenticate_TBasicUserValidationService_invalid_key_unauthotized()
		{
			using var request = new HttpRequestMessage(HttpMethod.Get, TestServerBuilder.BaseUrl);
			request.Headers.Authorization = new AuthenticationHeaderValue(BasicDefaults.AuthenticationScheme, "<invalid>");
			using var response = await _clientWithService.SendAsync(request);
			Assert.False(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
		}

#if !(NET461 || NETSTANDARD2_0 || NETCOREAPP2_1)

		[Fact]
		public async Task HandleAuthenticate_IgnoreAuthenticationIfAllowAnonymous()
		{
			using var response = await _clientWithService.GetAsync(TestServerBuilder.AnonymousUrl);
			var principal = await DeserializeClaimsPrincipalAsync(response);

			Assert.True(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.OK, response.StatusCode);
			Assert.False(principal.Identity.IsAuthenticated);
		}

#endif

		[Fact]
		public async Task HandleAuthenticate_Password_empty()
		{
			using var request = new HttpRequestMessage(HttpMethod.Get, TestServerBuilder.BaseUrl);
			request.Headers.Authorization = FakeUsers.FakeUserWithEmptyPassword.ToAuthenticationHeaderValue();
			using var response = await _clientWithService.SendAsync(request);

			Assert.True(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.OK, response.StatusCode);
		}

		[Fact]
		public async Task HandleAuthenticate_OnValidateCredentials_result_not_null()
		{
			using var server = TestServerBuilder.BuildTestServerWithService(options =>
			{
				options.Realm = TestServerBuilder.Realm;
				options.Events.OnValidateCredentials = context =>
				{
					context.ValidationSucceeded(new List<Claim> { FakeUsers.FakeRoleClaim, new(ClaimTypes.Name, "my_test") });

					Assert.NotNull(context.Result);

					return Task.CompletedTask;
				};
			});
			using var client = server.CreateClient();
			using var request = new HttpRequestMessage(HttpMethod.Get, TestServerBuilder.ClaimsPrincipalUrl);
			request.Headers.Authorization = FakeUsers.FakeUser.ToAuthenticationHeaderValue();
			using var response = await client.SendAsync(request);
			var principal = await DeserializeClaimsPrincipalAsync(response);

			Assert.True(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.OK, response.StatusCode);
			Assert.Contains(principal.Claims, c => c.Type == FakeUsers.FakeRoleClaim.Type && c.Value == FakeUsers.FakeRoleClaim.Value);
		}

		[Fact]
		public async Task HandleAuthenticate_OnValidateCredentials_result_null()
		{
			using var server = TestServerBuilder.BuildTestServerWithService(options =>
			{
				options.Realm = TestServerBuilder.Realm;
				options.Events.OnValidateCredentials = context =>
				{
					Assert.Null(context.Result);

					return Task.CompletedTask;
				};
			});
			using var client = server.CreateClient();
			using var request = new HttpRequestMessage(HttpMethod.Get, TestServerBuilder.ClaimsPrincipalUrl);
			request.Headers.Authorization = FakeUsers.FakeUser.ToAuthenticationHeaderValue();
			using var response = await client.SendAsync(request);
			var principal = await DeserializeClaimsPrincipalAsync(response);

			Assert.True(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.OK, response.StatusCode);
			Assert.Contains(principal.Claims, c => c.Type == FakeUsers.FakeNameClaim.Type && c.Value == FakeUsers.FakeNameClaim.Value);     // coming from provider, so provider called
		}

		[Fact]
		public async Task HandleAuthenticate_OnValidateCredentials_result_null_without_provider_and_OnAuthenticationFailed_throws()
		{
			var expectedExceptionMessage = $"Either {nameof(BasicEvents.OnValidateCredentials)} delegate on configure options {nameof(BasicOptions.Events)} should be set or use an extention method with type parameter of type {nameof(IBasicUserValidationService)}.";

			using var server = TestServerBuilder.BuildTestServer(options =>
			{
				options.Realm = TestServerBuilder.Realm;
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
			using var request = new HttpRequestMessage(HttpMethod.Get, TestServerBuilder.BaseUrl);
			request.Headers.Authorization = FakeUsers.FakeUser.ToAuthenticationHeaderValue();

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
			var expectedExceptionMessage = $"Either {nameof(BasicEvents.OnValidateCredentials)} delegate on configure options {nameof(BasicOptions.Events)} should be set or use an extention method with type parameter of type {nameof(IBasicUserValidationService)}.";

			using var server = TestServerBuilder.BuildTestServer(options =>
			{
				options.Realm = TestServerBuilder.Realm;
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
			using var request = new HttpRequestMessage(HttpMethod.Get, TestServerBuilder.BaseUrl);
			request.Headers.Authorization = FakeUsers.FakeUser.ToAuthenticationHeaderValue();
			using var response = await client.SendAsync(request);

			Assert.False(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
		}

		[Fact]
		public async Task HandleAuthenticate_OnAuthenticationSucceeded_result_null()
		{
			using var server = TestServerBuilder.BuildTestServerWithService(options =>
			{
				options.Realm = TestServerBuilder.Realm;
				options.Events.OnAuthenticationSucceeded = context =>
				{
					Assert.Null(context.Result);

					return Task.CompletedTask;
				};
			});
			using var client = server.CreateClient();
			using var request = new HttpRequestMessage(HttpMethod.Get, TestServerBuilder.BaseUrl);
			request.Headers.Authorization = FakeUsers.FakeUser.ToAuthenticationHeaderValue();
			using var response = await client.SendAsync(request);

			Assert.True(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.OK, response.StatusCode);
		}

		[Fact]
		public async Task HandleAuthenticate_OnAuthenticationSucceeded_result_and_principal_null()
		{
			using var server = TestServerBuilder.BuildTestServerWithService(options =>
			{
				options.Realm = TestServerBuilder.Realm;
				options.Events.OnAuthenticationSucceeded = context =>
				{
					context.RejectPrincipal();
					
					Assert.Null(context.Result);
					Assert.Null(context.Principal);

					return Task.CompletedTask;
				};
			});
			using var client = server.CreateClient();
			using var request = new HttpRequestMessage(HttpMethod.Get, TestServerBuilder.BaseUrl);
			request.Headers.Authorization = FakeUsers.FakeUser.ToAuthenticationHeaderValue();
			using var response = await client.SendAsync(request);

			Assert.False(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
		}

		[Fact]
		public async Task HandleAuthenticate_OnAuthenticationSucceeded_result_not_null()
		{
			using var server = TestServerBuilder.BuildTestServerWithService(options =>
			{
				options.Realm = TestServerBuilder.Realm;
				options.Events.OnAuthenticationSucceeded = context =>
				{
					context.Fail("test");

					Assert.NotNull(context.Result);
					Assert.NotNull(context.Principal);

					return Task.CompletedTask;
				};
			});
			using var client = server.CreateClient();
			using var request = new HttpRequestMessage(HttpMethod.Get, TestServerBuilder.BaseUrl);
			request.Headers.Authorization = FakeUsers.FakeUser.ToAuthenticationHeaderValue();
			using var response = await client.SendAsync(request);

			Assert.False(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
		}

		#endregion // HandleAuthenticate

		#region Multi-Scheme

		[Fact]
		public async Task MultiScheme()
		{
			var claimRole = new ClaimDto(FakeUsers.FakeRoleClaim);
			var schemes = new List<string> { "Scheme1", "Scheme2", };

			using var server = TestServerBuilder.BuildTestServer(services =>
			{
				services.AddAuthentication("Scheme1")
					.AddBasic("Scheme1", options =>
					{
						options.Realm = TestServerBuilder.Realm;
						options.Events.OnValidateCredentials = context =>
						{
							var user = FakeUsers.Users.FirstOrDefault(u => u.Username.Equals(context.Username, StringComparison.OrdinalIgnoreCase) && u.Password.Equals(context.Password, StringComparison.OrdinalIgnoreCase));
							if (user != null)
							{
								context.Response.Headers["X-Custom"] = "Scheme1";
								context.ValidationSucceeded(new List<Claim> { FakeUsers.FakeRoleClaim });
							}
							else
							{
								context.ValidationFailed();
							}
							return Task.CompletedTask;
						};
					})
					.AddBasic<FakeBasicUserValidationServiceLocal_1>("Scheme2", options =>
					{
						options.Realm = TestServerBuilder.Realm;
					});

#if !(NET461 || NETSTANDARD2_0 || NETCOREAPP2_1)
				services.Configure<AuthorizationOptions>(options => options.FallbackPolicy = new AuthorizationPolicyBuilder(schemes.ToArray()).RequireAuthenticatedUser().Build());
#endif
			});

			using var client = server.CreateClient();

			using var request1 = new HttpRequestMessage(HttpMethod.Get, TestServerBuilder.ClaimsPrincipalUrl + "?scheme=" + schemes[0]);
			request1.Headers.Authorization = FakeUsers.FakeUser.ToAuthenticationHeaderValue();
			using var response1 = await client.SendAsync(request1);
			Assert.True(response1.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.OK, response1.StatusCode);
			var response1Principal = await DeserializeClaimsPrincipalAsync(response1);
			Assert.Contains(response1.Headers, r => r.Key == "X-Custom" && r.Value.Any(v => v == "Scheme1"));
			Assert.Contains(response1Principal.Claims, c => c.Type == claimRole.Type && c.Value == claimRole.Value);


			using var request2 = new HttpRequestMessage(HttpMethod.Get, TestServerBuilder.ClaimsPrincipalUrl + "?scheme=" + schemes[1]);
			request2.Headers.Authorization = new User("test", "test").ToAuthenticationHeaderValue();
			using var response2 = await client.SendAsync(request2);
			Assert.True(response2.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.OK, response2.StatusCode);
			var response2Principal = await DeserializeClaimsPrincipalAsync(response2);
			Assert.DoesNotContain(response2.Headers, r => r.Key == "X-Custom" && r.Value.Any(v => v == "Scheme1"));
			Assert.DoesNotContain(response2Principal.Claims, c => c.Type == claimRole.Type && c.Value == claimRole.Value);
		}

		#endregion // Multi-Scheme

		private async Task<ClaimsPrincipalDto> DeserializeClaimsPrincipalAsync(HttpResponseMessage response)
		{
			return JsonSerializer.Deserialize<ClaimsPrincipalDto>(await response.Content.ReadAsStringAsync());
		}

		private class FakeBasicUserValidationServiceLocal_1 : IBasicUserValidationService
		{
			public Task<bool> IsValidAsync(string username, string password)
			{
				return Task.FromResult(true);
			}
		}

		private class FakeBasicUserValidationServiceLocal_2 : IBasicUserValidationService
		{
			public Task<bool> IsValidAsync(string username, string password)
			{
				return Task.FromResult(true);
			}
		}
	}
}
