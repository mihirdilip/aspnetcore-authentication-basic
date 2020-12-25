using AspNetCore.Authentication.Basic;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Authorization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using SampleWebApi.Repositories;
using SampleWebApi.Services;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;

namespace SampleWebApi_3_1
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            // Add User repository to the dependency container.
            services.AddTransient<IUserRepository, InMemoryUserRepository>();

            // Add the Basic scheme authentication here..
            // It requires Realm to be set in the options if SuppressWWWAuthenticateHeader is not set.
            // If an implementation of IBasicUserValidationService interface is registered in the dependency register as well as OnValidateCredentials delegete on options.Events is also set then this delegate will be used instead of an implementation of IBasicUserValidationService.
            services.AddAuthentication(BasicDefaults.AuthenticationScheme)

                // The below AddBasic without type parameter will require OnValidateCredentials delegete on options.Events to be set unless an implementation of IBasicUserValidationService interface is registered in the dependency register.
                // Please note if both the delgate and validation server are set then the delegate will be used instead of BasicUserValidationService.
                //.AddBasic(options =>

                // The below AddBasic with type parameter will add the BasicUserValidationService to the dependency register. 
                // Please note if OnValidateCredentials delegete on options.Events is also set then this delegate will be used instead of BasicUserValidationService.
                .AddBasic<BasicUserValidationService>(options =>
                {
                    options.Realm = "Sample Web API";

                    //// Optional option to suppress the browser login dialog for ajax calls.
                    //options.SuppressWWWAuthenticateHeader = true;

                    //// Optional option to ignore authentication if AllowAnonumous metadata/filter attribute is added to an endpoint.
                    //options.IgnoreAuthenticationIfAllowAnonymous = true;

                    //// Optional events to override the basic original logic with custom logic.
                    //// Only use this if you know what you are doing at your own risk. Any of the events can be assigned. 
                    options.Events = new BasicEvents
                    {

                        //// A delegate assigned to this property will be invoked just before validating credentials. 
                        //OnValidateCredentials = async (context) =>
                        //{
                        //    // custom code to handle credentials, create principal and call Success method on context.
                        //    var userRepository = context.HttpContext.RequestServices.GetRequiredService<IUserRepository>();
                        //    var user = await userRepository.GetUserByUsername(context.Username);
                        //    var isValid = user != null && user.Password == context.Password;
                        //    if (isValid)
                        //    {
                        //        context.Response.Headers.Add("ValidationCustomHeader", "From OnValidateCredentials");
                        //        var claims = new[]
                        //        {
                        //            new Claim(ClaimTypes.NameIdentifier, context.Username, ClaimValueTypes.String, context.Options.ClaimsIssuer),
                        //            new Claim(ClaimTypes.Name, context.Username, ClaimValueTypes.String, context.Options.ClaimsIssuer),
                        //            new Claim("CustomClaimType", "Custom Claim Value - from OnValidateCredentials")
                        //        };
                        //        context.Principal = new ClaimsPrincipal(new ClaimsIdentity(claims, context.Scheme.Name));
                        //        context.Success();
                        //    }
                        //    else
                        //    {
                        //        context.NoResult();
                        //    }
                        //},

                        //// A delegate assigned to this property will be invoked just before validating credentials. 
                        //// NOTE: Same as above delegate but slightly different implementation which will give same result.
                        //OnValidateCredentials = async (context) =>
                        //{
                        //    // custom code to handle credentials, create principal and call Success method on context.
                        //    var userRepository = context.HttpContext.RequestServices.GetRequiredService<IUserRepository>();
                        //    var user = await userRepository.GetUserByUsername(context.Username);
                        //    var isValid = user != null && user.Password == context.Password;
                        //    if (isValid)
                        //    {
                        //        context.Response.Headers.Add("ValidationCustomHeader", "From OnValidateCredentials");
                        //        var claims = new[]
                        //        {
                        //            new Claim("CustomClaimType", "Custom Claim Value - from OnValidateCredentials")
                        //        };
                        //        context.ValidationSucceeded(claims);    // claims are optional
                        //    }
                        //    else
                        //    {
                        //        context.ValidationFailed();
                        //    }
                        //},

                        //// A delegate assigned to this property will be invoked before a challenge is sent back to the caller when handling unauthorized response.
                        //OnHandleChallenge = async (context) =>
                        //{
                        //    // custom code to handle authentication challenge unauthorized response.
                        //    context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                        //    context.Response.Headers.Add("ChallengeCustomHeader", "From OnHandleChallenge");
                        //    await context.Response.WriteAsync("{\"CustomBody\":\"From OnHandleChallenge\"}");
                        //    context.Handled();  // important! do not forget to call this method at the end.
                        //},

                        //// A delegate assigned to this property will be invoked if Authorization fails and results in a Forbidden response.
                        //OnHandleForbidden = async (context) =>
                        //{
                        //    // custom code to handle forbidden response.
                        //    context.Response.StatusCode = StatusCodes.Status403Forbidden;
                        //    context.Response.Headers.Add("ForbidCustomHeader", "From OnHandleForbidden");
                        //    await context.Response.WriteAsync("{\"CustomBody\":\"From OnHandleForbidden\"}");
                        //    context.Handled();  // important! do not forget to call this method at the end.
                        //},

                        //// A delegate assigned to this property will be invoked when the authentication succeeds. It will not be called if OnValidateCredentials delegate is assigned.
                        //// It can be used for adding claims, headers, etc to the response.
                        //OnAuthenticationSucceeded = (context) =>
                        //{
                        //    //custom code to add extra bits to the success response.
                        //    context.Response.Headers.Add("SuccessCustomHeader", "From OnAuthenticationSucceeded");
                        //    var customClaims = new List<Claim>
                        //    {
                        //        new Claim("CustomClaimType", "Custom Claim Value - from OnAuthenticationSucceeded")
                        //    };
                        //    context.AddClaims(customClaims);
                        //    //or can add like this - context.Principal.AddIdentity(new ClaimsIdentity(customClaims));
                        //    return Task.CompletedTask;
                        //},

                        //// A delegate assigned to this property will be invoked when the authentication fails.
                        //OnAuthenticationFailed = (context) =>
                        //{
                        //    // custom code to handle failed authentication.
                        //    context.Fail("Failed to authenticate");
                        //    return Task.CompletedTask;
                        //}

                    };
                });

            services.AddControllers(options =>
            {
                // ALWAYS USE HTTPS (SSL) protocol in production when using ApiKey authentication.
                //options.Filters.Add<RequireHttpsAttribute>();

            }); //.AddXmlSerializerFormatters()   // To enable XML along with JSON;

            // All the requests will need to be authorized. 
            // Alternatively, add [Authorize] attribute to Controller or Action Method where necessary.
            services.AddAuthorization(options =>
            {
                options.FallbackPolicy = new AuthorizationPolicyBuilder()
                    .RequireAuthenticatedUser()
                    .Build();
            });
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            // The below order of pipeline chain is important!

            app.UseHttpsRedirection();
            app.UseRouting();

            app.UseAuthentication();    // NOTE: DEFAULT TEMPLATE DOES NOT HAVE THIS, THIS LINE IS REQUIRED AND HAS TO BE ADDED!!!

            app.UseAuthorization();
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }
    }
}
