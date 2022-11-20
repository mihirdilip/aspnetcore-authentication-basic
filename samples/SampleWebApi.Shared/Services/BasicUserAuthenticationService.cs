namespace SampleWebApi.Services
{
	using System;
	using System.Threading.Tasks;
	using MadEyeMatt.AspNetCore.Authentication.Basic;
	using Microsoft.Extensions.Logging;
	using SampleWebApi.Models;
	using SampleWebApi.Repositories;

	internal class BasicUserAuthenticationService : IBasicUserAuthenticationService
	{
		private readonly ILogger<BasicUserAuthenticationService> logger;
		private readonly IUserRepository userRepository;

		public BasicUserAuthenticationService(ILogger<BasicUserAuthenticationService> logger, IUserRepository userRepository)
		{
			this.logger = logger;
			this.userRepository = userRepository;
		}

		public async Task<MadEyeMatt.AspNetCore.Authentication.Basic.IBasicUser> AuthenticateAsync(string username, string password)
		{
			try
			{
				// NOTE: DO NOT USE THIS IMPLEMENTATION. THIS IS FOR DEMO PURPOSE ONLY
				// Write your implementation here and return true or false depending on the validation..
				User user = await this.userRepository.GetUserByUsername(username);
				bool isValid = user != null && user.Password == password;
				return isValid ? new BasicUser(username) : null;
			}
			catch(Exception e)
			{
				this.logger.LogError(e, e.Message);
				throw;
			}
		}
	}
}
