// Copyright (c) Mihir Dilip. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

namespace MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Events
{
	using System;
	using System.Collections.Generic;
	using System.Linq;
	using System.Net;
	using System.Net.Http;
	using System.Security.Claims;
	using System.Text.Json;
	using System.Threading.Tasks;
	using MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure;
	using Microsoft.AspNetCore.TestHost;
	using Xunit;

	public class BasicValidateCredentialsContextTests : IDisposable
	{
		public void Dispose()
		{
			this._serversToDispose.ForEach(s => s.Dispose());
		}

		private readonly List<TestServer> _serversToDispose = new List<TestServer>();


		private HttpClient BuildClient(Func<MadEyeMatt.AspNetCore.Authentication.Basic.Events.BasicValidateCredentialsContext, Task> onValidateCredentials)
		{
			TestServer server = MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.TestServerBuilder.BuildTestServer(options =>
			{
				options.Realm = MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.TestServerBuilder.Realm;
				options.Events.OnValidateCredentials = onValidateCredentials;
			});

			this._serversToDispose.Add(server);
			return server.CreateClient();
		}

		private async Task RunUnauthorizedTests(HttpClient client)
		{
			using HttpResponseMessage response_unauthorized = await client.GetAsync(MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.TestServerBuilder.ClaimsPrincipalUrl);
			Assert.False(response_unauthorized.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.Unauthorized, response_unauthorized.StatusCode);
		}

		private async Task<MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.ClaimsPrincipalDto> RunSuccessTests(HttpClient client)
		{
			using HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.TestServerBuilder.ClaimsPrincipalUrl);
			request.Headers.Authorization = MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.FakeUsers.FakeUser.ToAuthenticationHeaderValue();
			using HttpResponseMessage response_ok = await client.SendAsync(request);
			Assert.True(response_ok.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.OK, response_ok.StatusCode);

			string content = await response_ok.Content.ReadAsStringAsync();
			Assert.False(string.IsNullOrWhiteSpace(content));
			return JsonSerializer.Deserialize<MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.ClaimsPrincipalDto>(content);
		}

		[Fact]
		public async Task Success_and_NoResult()
		{
			using HttpClient client = this.BuildClient(
				context =>
				{
					Assert.Null(context.Principal);
					Assert.Null(context.Result);
					Assert.False(string.IsNullOrWhiteSpace(context.Username));

					User user = MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.FakeUsers.Users.FirstOrDefault(u => u.Username.Equals(context.Username, StringComparison.OrdinalIgnoreCase) && u.Password.Equals(context.Password, StringComparison.OrdinalIgnoreCase));
					if(user != null)
					{
						context.Principal = new ClaimsPrincipal(new ClaimsIdentity(context.Scheme.Name));
						context.Success();

						Assert.NotNull(context.Principal);
						Assert.NotNull(context.Result);
						Assert.NotNull(context.Result.Principal);
						Assert.True(context.Result.Succeeded);
					}
					else
					{
						context.NoResult();

						Assert.Null(context.Principal);
						Assert.NotNull(context.Result);
						Assert.Null(context.Result.Principal);
						Assert.False(context.Result.Succeeded);
						Assert.True(context.Result.None);
					}

					return Task.CompletedTask;
				}
			);

			ClaimsPrincipalDto principal = await this.RunSuccessTests(client);
			Assert.Empty(principal.Claims);

			await this.RunUnauthorizedTests(client);
		}

		[Fact]
		public async Task ValidationFailed_with_failureException()
		{
			using HttpClient client = this.BuildClient(
				context =>
				{
					Exception failureException = new Exception();
					context.ValidationFailed(failureException);

					Assert.Null(context.Principal);
					Assert.NotNull(context.Result);
					Assert.Null(context.Result.Principal);
					Assert.False(context.Result.Succeeded);
					Assert.NotNull(context.Result.Failure);
					Assert.Equal(failureException, context.Result.Failure);

					return Task.CompletedTask;
				}
			);

			await this.RunUnauthorizedTests(client);
		}

		[Fact]
		public async Task ValidationFailed_with_failureMessage()
		{
			using HttpClient client = this.BuildClient(
				context =>
				{
					string failureMessage = "failure message";
					context.ValidationFailed(failureMessage);

					Assert.Null(context.Principal);
					Assert.NotNull(context.Result);
					Assert.Null(context.Result.Principal);
					Assert.False(context.Result.Succeeded);
					Assert.NotNull(context.Result.Failure);
					Assert.Equal(failureMessage, context.Result.Failure.Message);

					return Task.CompletedTask;
				}
			);

			await this.RunUnauthorizedTests(client);
		}

		[Fact]
		public async Task ValidationSucceeded_and_ValidationFailed()
		{
			using HttpClient client = this.BuildClient(
				context =>
				{
					User user = MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.FakeUsers.Users.FirstOrDefault(u => u.Username.Equals(context.Username, StringComparison.OrdinalIgnoreCase) && u.Password.Equals(context.Password, StringComparison.OrdinalIgnoreCase));
					if(user != null)
					{
						context.ValidationSucceeded();

						Assert.NotNull(context.Principal);
						Assert.NotNull(context.Result);
						Assert.NotNull(context.Result.Principal);
						Assert.True(context.Result.Succeeded);
					}
					else
					{
						context.ValidationFailed();

						Assert.Null(context.Principal);
						Assert.NotNull(context.Result);
						Assert.Null(context.Result.Principal);
						Assert.False(context.Result.Succeeded);
						Assert.True(context.Result.None);
					}

					return Task.CompletedTask;
				}
			);

			await this.RunSuccessTests(client);
			await this.RunUnauthorizedTests(client);
		}

		[Fact]
		public async Task ValidationSucceeded_with_claims()
		{
			List<Claim> claimsSource = new List<Claim>
			{
				MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.FakeUsers.FakeNameClaim,
				MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.FakeUsers.FakeRoleClaim
			};

			using HttpClient client = this.BuildClient(
				context =>
				{
					context.ValidationSucceeded(claimsSource);

					Assert.NotNull(context.Principal);
					Assert.NotNull(context.Result);
					Assert.NotNull(context.Result.Principal);
					Assert.True(context.Result.Succeeded);

					return Task.CompletedTask;
				}
			);

			ClaimsPrincipalDto principal = await this.RunSuccessTests(client);
			Assert.NotEmpty(principal.Claims);

			Assert.Equal(claimsSource.Count + 1, principal.Claims.Count());
			Assert.Contains(new MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.ClaimDto(MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.FakeUsers.FakeNameClaim), principal.Claims);
			Assert.Contains(new MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.ClaimDto(MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.FakeUsers.FakeRoleClaim), principal.Claims);
		}
	}
}
