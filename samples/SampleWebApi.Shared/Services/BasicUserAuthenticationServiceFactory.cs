using System.Diagnostics;
using Microsoft.Extensions.Logging;
using SampleWebApi.Repositories;

namespace SampleWebApi.Services
{
	internal class BasicUserAuthenticationServiceFactory : MadEyeMatt.AspNetCore.Authentication.Basic.IBasicUserAuthenticationServiceFactory
	{
		private readonly ILoggerFactory loggerFactory;
		private readonly IUserRepository userRepository;

		public BasicUserAuthenticationServiceFactory(ILoggerFactory loggerFactory, IUserRepository userRepository)
		{
			this.loggerFactory = loggerFactory;
			this.userRepository = userRepository;
		}

		/// <inheritdoc />
		public MadEyeMatt.AspNetCore.Authentication.Basic.IBasicUserAuthenticationService CreateBasicUserAuthenticationService(string authenticationSchemaName)
		{
			Debug.WriteLine(authenticationSchemaName);
			return new BasicUserAuthenticationService(this.loggerFactory.CreateLogger<BasicUserAuthenticationService>(), this.userRepository);
		}
	}
}
