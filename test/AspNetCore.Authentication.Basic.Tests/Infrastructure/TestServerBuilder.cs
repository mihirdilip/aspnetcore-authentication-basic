// Copyright (c) Mihir Dilip. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Primitives;
using System;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;

namespace AspNetCore.Authentication.Basic.Tests.Infrastructure
{
    partial class TestServerBuilder
    {
        internal static string BaseUrl = "http://localhost/";
        internal static string AnonymousUrl = $"{BaseUrl}anonymous";
        internal static string ForbiddenUrl = $"{BaseUrl}forbidden";
        internal static string ClaimsPrincipalUrl = $"{BaseUrl}claims-principal";
        internal static string Realm = "BasicTests";

        internal static TestServer BuildTestServer(Action<BasicOptions>? configureOptions = null)
        {
            return BuildTestServer(
                services =>
                {
                    var authBuilder = services.AddAuthentication(BasicDefaults.AuthenticationScheme)
                        .AddBasic(configureOptions ?? DefaultBasicOptionsWithOnValidateCredentials());
                }
            );
        }

        internal static TestServer BuildTestServerWithService(Action<BasicOptions>? configureOptions = null)
        {
            return BuildTestServer(
                services =>
                {
                    var authBuilder = services.AddAuthentication(BasicDefaults.AuthenticationScheme)
                        .AddBasic<FakeBasicUserValidationService>(configureOptions ?? DefaultBasicOptions());
                }
            );
        }

        internal static TestServer BuildTestServer(Action<IServiceCollection> configureServices, Action<IApplicationBuilder>? configure = null)
        {
            if (configureServices == null) throw new ArgumentNullException(nameof(configureServices));

            return new TestServer(
                new WebHostBuilder()

                    .ConfigureServices(services =>
                    {

#if !(NET461 || NETSTANDARD2_0 || NETCOREAPP2_1)
                        services.AddRouting();
                        services.AddAuthorization(options => options.FallbackPolicy = new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build());
#endif

                        configureServices(services);

                    })


                    .Configure(app =>
                    {

#if !(NET461 || NETSTANDARD2_0 || NETCOREAPP2_1)
                        
                        app.UseRouting();
                        app.UseAuthentication();
                        app.UseAuthorization();

                        if (configure != null)
                        {
                            configure(app);
                        }
                        else
                        {
                            app.UseEndpoints(endpoints =>
                            {
                                endpoints.MapGet("/", async context =>
                                {
                                    await context.Response.WriteAsync("Hello World!");
                                });

                                endpoints.MapGet("/claims-principal", async context =>
                                {
                                    context.Response.ContentType = "application/json";
                                    await context.Response.WriteAsync(JsonSerializer.Serialize(new ClaimsPrincipalDto(context.User)));
                                });

                                endpoints.MapGet("/forbidden", async context =>
                                {
                                    await context.ForbidAsync();
                                });

                                endpoints.MapGet("/anonymous", async context =>
                                {
                                    await context.Response.WriteAsync(JsonSerializer.Serialize(new ClaimsPrincipalDto(context.User)));
                                }).WithMetadata(new Microsoft.AspNetCore.Authorization.AllowAnonymousAttribute());
                            });
                        }

#else

                        app.UseAuthentication();

                        if (configure != null)
                        {
                            configure(app);
                        }
                        else
                        {
                            app.Run(async (context) =>
                            {
                                if (!context.User.Identity.IsAuthenticated)
                                {
                                    var scheme = StringValues.Empty;
                                    context.Request.Query.TryGetValue("scheme", out scheme);

                                    if (scheme.Any())
                                    {
                                        var result = await context.AuthenticateAsync(scheme);
                                        if (result?.Principal != null)
                                        {
                                            context.User = result.Principal;
                                        }
                                        else
                                        {
                                            await context.ChallengeAsync(scheme);
                                            return;
                                        }
                                    }
                                    else
                                    {
                                        await context.ChallengeAsync();
                                        return;
                                    }
                                }



                                if (context.Request.Path == "/claims-principal")
                                {
                                    context.Response.ContentType = "application/json";
                                    await context.Response.WriteAsync(JsonSerializer.Serialize(new ClaimsPrincipalDto(context.User)));
                                    return;
                                }

                                if (context.Request.Path == "/forbidden")
                                {
                                    await context.ForbidAsync();
                                }

                                await context.Response.WriteAsync("Hello World!");
                            });
                        }

#endif

                    })
            );
        }



        private static Action<BasicOptions> DefaultBasicOptions()
        {
            return options =>
            {
                options.Realm = Realm;
            };
        }

        private static Action<BasicOptions> DefaultBasicOptionsWithOnValidateCredentials()
        {
            return options =>
            {
                options.Realm = Realm;
                options.Events.OnValidateCredentials =
                    context =>
                    {
                        var user = FakeUsers.Users.FirstOrDefault(u => u.Username.Equals(context.Username, StringComparison.OrdinalIgnoreCase) && u.Password.Equals(context.Password, StringComparison.OrdinalIgnoreCase));
                        if (user != null)
                        {
                            context.ValidationSucceeded();
                        }
                        else
                        {
                            context.ValidationFailed();
                        }
                        return Task.CompletedTask;
                    };
            };
        }
    }
}
