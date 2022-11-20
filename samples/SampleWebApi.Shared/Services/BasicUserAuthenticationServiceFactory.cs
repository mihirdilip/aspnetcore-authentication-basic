namespace SampleWebApi.Services
{
	using System.Diagnostics;
	using MadEyeMatt.AspNetCore.Authentication.Basic;
	using Microsoft.Extensions.Logging;
	using SampleWebApi.Repositories;

	internal class BasicUserAuthenticationServiceFactory : IBasicUserAuthenticationServiceFactory
	{
		private readonly ILoggerFactory loggerFactory;
		private readonly IUserRepository userRepository;

		public BasicUserAuthenticationServiceFactory(ILoggerFactory loggerFactory, IUserRepository userRepository)
		{
			this.loggerFactory = loggerFactory;
			this.userRepository = userRepository;
		}

		/// <inheritdoc />
		public IBasicUserAuthenticationService CreateBasicUserAuthenticationService(string authenticationSchemaName)
		{
			Debug.WriteLine(authenticationSchemaName);
			return new BasicUserAuthenticationService(this.loggerFactory.CreateLogger<BasicUserAuthenticationService>(), this.userRepository);
		}
	}
}
