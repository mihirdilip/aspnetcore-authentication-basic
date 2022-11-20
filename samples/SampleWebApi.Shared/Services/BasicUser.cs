namespace SampleWebApi.Services
{
	using System.Collections.Generic;
	using System.Security.Claims;

    internal class BasicUser : MadEyeMatt.AspNetCore.Authentication.Basic.IBasicUser
	{
		public BasicUser(string userName, List<Claim> claims = null)
		{
			this.UserName = userName;
			this.Claims = claims ?? new List<Claim>();
		}

		/// <inheritdoc />
		public string UserName { get; }

		/// <inheritdoc />
		public IReadOnlyCollection<Claim> Claims { get; }
	}
}
