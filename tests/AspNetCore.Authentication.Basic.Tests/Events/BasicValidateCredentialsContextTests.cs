// Copyright (c) Mihir Dilip. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

using AspNetCore.Authentication.Basic.Tests.Infrastructure;
using Microsoft.AspNetCore.TestHost;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Text.Json;
using System.Threading.Tasks;
using Xunit;

namespace AspNetCore.Authentication.Basic.Tests.Events
{
    public class BasicValidateCredentialsContextTests : IDisposable
    {
        private readonly List<TestServer> _serversToDispose = new List<TestServer>();

        public void Dispose()
        {
            _serversToDispose.ForEach(s => s.Dispose());
        }

        [Fact]
        public async Task Success_and_NoResult()
        {
            using var client = BuildClient(
                context =>
                {
                    Assert.Null(context.Principal);
                    Assert.Null(context.Result);
                    Assert.False(string.IsNullOrWhiteSpace(context.Username));

                    var user = FakeUsers.Users.FirstOrDefault(u => u.Username.Equals(context.Username, StringComparison.OrdinalIgnoreCase) && u.Password.Equals(context.Password, StringComparison.OrdinalIgnoreCase));
                    if (user != null)
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

            var principal = await RunSuccessTests(client);
            Assert.Empty(principal.Claims);

            await RunUnauthorizedTests(client);
        }

        [Fact]
        public async Task ValidationSucceeded_and_ValidationFailed()
        {
            using var client = BuildClient(
                context =>
                {
                    var user = FakeUsers.Users.FirstOrDefault(u => u.Username.Equals(context.Username, StringComparison.OrdinalIgnoreCase) && u.Password.Equals(context.Password, StringComparison.OrdinalIgnoreCase));
                    if (user != null)
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

            await RunSuccessTests(client);
            await RunUnauthorizedTests(client);
        }

        [Fact]
        public async Task ValidationSucceeded_with_claims()
        {
            var claimsSource = new List<Claim>
            {
                FakeUsers.FakeNameClaim,
                FakeUsers.FakeRoleClaim
            };

            using var client = BuildClient(
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

            var principal = await RunSuccessTests(client);
            Assert.NotEmpty(principal.Claims);

            Assert.Equal(claimsSource.Count + 1, principal.Claims.Count());
            Assert.Contains(new ClaimDto(FakeUsers.FakeNameClaim), principal.Claims);
            Assert.Contains(new ClaimDto(FakeUsers.FakeRoleClaim), principal.Claims);
        }

        [Fact]
        public async Task ValidationFailed_with_failureMessage()
        {
            using var client = BuildClient(
                context =>
                {
                    var failureMessage = "failure message";
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

            await RunUnauthorizedTests(client);
        }

        [Fact]
        public async Task ValidationFailed_with_failureException()
        {
            using var client = BuildClient(
                context =>
                {
                    var failureException = new Exception();
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

            await RunUnauthorizedTests(client);
        }



        private HttpClient BuildClient(Func<BasicValidateCredentialsContext, Task> onValidateCredentials)
        {
            var server = TestServerBuilder.BuildTestServer(options =>
            {
                options.Realm = TestServerBuilder.Realm;
                options.Events.OnValidateCredentials = onValidateCredentials;
            });

            _serversToDispose.Add(server);
            return server.CreateClient();
        }

        private async Task RunUnauthorizedTests(HttpClient client)
        {
            using var response_unauthorized = await client.GetAsync(TestServerBuilder.ClaimsPrincipalUrl);
            Assert.False(response_unauthorized.IsSuccessStatusCode);
            Assert.Equal(HttpStatusCode.Unauthorized, response_unauthorized.StatusCode);
        }

        private async Task<ClaimsPrincipalDto> RunSuccessTests(HttpClient client)
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, TestServerBuilder.ClaimsPrincipalUrl);
            request.Headers.Authorization = FakeUsers.FakeUser.ToAuthenticationHeaderValue();
            using var response_ok = await client.SendAsync(request);
            Assert.True(response_ok.IsSuccessStatusCode);
            Assert.Equal(HttpStatusCode.OK, response_ok.StatusCode);

            var content = await response_ok.Content.ReadAsStringAsync();
            Assert.False(string.IsNullOrWhiteSpace(content));
            return JsonSerializer.Deserialize<ClaimsPrincipalDto>(content);
        }
    }
}
