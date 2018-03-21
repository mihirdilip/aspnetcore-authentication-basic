using System;
using Microsoft.Extensions.Options;

namespace Mihir.AspNetCore.Authentication.Basic
{
	class BasicPostConfigureOptions : IPostConfigureOptions<BasicOptions>
	{
		public void PostConfigure(string name, BasicOptions options)
		{
			if (string.IsNullOrWhiteSpace(options.Realm))
			{
				throw new InvalidOperationException("Realm must be set in basic options");
			}
		}
	}
}
