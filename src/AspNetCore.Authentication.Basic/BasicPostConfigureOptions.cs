// Copyright (c) Mihir Dilip. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

using Microsoft.Extensions.Options;
using System;

namespace AspNetCore.Authentication.Basic
{
	/// <summary>
	/// This post configure options checks whether the required option property <see cref="BasicOptions.Realm" /> is set or not on <see cref="BasicOptions"/>.
	/// </summary>
	internal class BasicPostConfigureOptions : IPostConfigureOptions<BasicOptions>
	{
        private readonly IBasicUserValidationService _basicUserValidationService;

        public BasicPostConfigureOptions(IBasicUserValidationService basicUserValidationService)
        {
            _basicUserValidationService = basicUserValidationService ?? throw new ArgumentNullException(nameof(basicUserValidationService));
        }

		public void PostConfigure(string name, BasicOptions options)
		{
			if (!options.SuppressWWWAuthenticateHeader && string.IsNullOrWhiteSpace(options.Realm))
			{
				throw new InvalidOperationException("Realm must be set in basic options");
			}

			if (options.Events?.OnValidateCredentials == null && options.EventsType == null && _basicUserValidationService is DefaultBasicUserValidationService)
            {
				throw new InvalidOperationException($"Either {nameof(options.Events.OnValidateCredentials)} delegate on configure options {nameof(options.Events)} should be set or an implementaion of {nameof(IBasicUserValidationService)} should be registered in the dependency container.");
			}
		}
	}
}
