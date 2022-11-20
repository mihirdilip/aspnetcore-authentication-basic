// Copyright (c) Mihir Dilip. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

namespace MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Events
{
	using System;
	using System.Collections.Generic;
	using System.Net;
	using System.Net.Http;
	using System.Security.Claims;
	using System.Text.Json;
	using System.Threading.Tasks;
	using MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure;
	using Microsoft.AspNetCore.TestHost;
	using Xunit;

	public class BasicAuthenticationSucceededContextTests : IDisposable
	{
		public void Dispose()
		{
			this._serversToDispose.ForEach(s => s.Dispose());
		}

		private readonly List<TestServer> _serversToDispose = new List<TestServer>();


		private HttpClient BuildClient(Func<MadEyeMatt.AspNetCore.Authentication.Basic.Events.BasicAuthenticationSucceededContext, Task> onAuthenticationSucceeded)
		{
			TestServer server = MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.TestServerBuilder.BuildTestServerWithService(options =>
			{
				options.Realm = MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.TestServerBuilder.Realm;
				options.Events.OnAuthenticationSucceeded = onAuthenticationSucceeded;
			});

			this._serversToDispose.Add(server);
			return server.CreateClient();
		}

		private async Task RunUnauthorizedTests(HttpClient client)
		{
			using HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.TestServerBuilder.ClaimsPrincipalUrl);
			request.Headers.Authorization = MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.FakeUsers.FakeUser.ToAuthenticationHeaderValue();
			using HttpResponseMessage response_unauthorized = await client.SendAsync(request);
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
		public async Task AddClaim()
		{
			Claim claim = new Claim(ClaimTypes.Actor, "Actor");

			using HttpClient client = this.BuildClient(
				context =>
				{
					context.AddClaim(claim);

					Assert.Contains(context.Principal.Claims, c => c.Type == claim.Type && c.Value == claim.Value);

					return Task.CompletedTask;
				}
			);

			ClaimsPrincipalDto principal = await this.RunSuccessTests(client);
			Assert.Contains(new MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.ClaimDto(claim), principal.Claims);
		}

		[Fact]
		public async Task AddClaims()
		{
			List<Claim> claims = new List<Claim>
			{
				new Claim(ClaimTypes.Actor, "Actor"),
				new Claim(ClaimTypes.Country, "Country")
			};

			using HttpClient client = this.BuildClient(
				context =>
				{
					context.AddClaims(claims);

					Assert.Contains(context.Principal.Claims, c => c.Type == claims[0].Type && c.Value == claims[0].Value);
					Assert.Contains(context.Principal.Claims, c => c.Type == claims[1].Type && c.Value == claims[1].Value);

					return Task.CompletedTask;
				}
			);

			ClaimsPrincipalDto principal = await this.RunSuccessTests(client);
			Assert.Contains(new MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.ClaimDto(claims[0]), principal.Claims);
			Assert.Contains(new MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.ClaimDto(claims[1]), principal.Claims);
		}

		[Fact]
		public async Task Principal_not_null()
		{
			using HttpClient client = this.BuildClient(
				context =>
				{
					Assert.NotNull(context.Principal);
					Assert.Null(context.Result);
					return Task.CompletedTask;
				}
			);

			ClaimsPrincipalDto principal = await this.RunSuccessTests(client);
			Assert.True(principal.Identity.IsAuthenticated);
		}

		[Fact]
		public async Task RejectPrincipal()
		{
			using HttpClient client = this.BuildClient(
				context =>
				{
					context.RejectPrincipal();

					Assert.Null(context.Principal);

					return Task.CompletedTask;
				}
			);

			await this.RunUnauthorizedTests(client);
		}

		[Fact]
		public async Task ReplacePrincipal()
		{
			using HttpClient client = this.BuildClient(
				context =>
				{
					ClaimsPrincipal newPrincipal = new ClaimsPrincipal();
					context.ReplacePrincipal(newPrincipal);

					Assert.NotNull(context.Principal);
					Assert.Equal(newPrincipal, context.Principal);

					return Task.CompletedTask;
				}
			);

			await this.RunUnauthorizedTests(client);
		}

		[Fact]
		public async Task ReplacePrincipal_null_throws_argument_null_exception()
		{
			using HttpClient client = this.BuildClient(
				context =>
				{
					Assert.Throws<ArgumentNullException>(() => context.ReplacePrincipal(null));
					return Task.CompletedTask;
				}
			);

			await this.RunSuccessTests(client);
		}
	}
}
