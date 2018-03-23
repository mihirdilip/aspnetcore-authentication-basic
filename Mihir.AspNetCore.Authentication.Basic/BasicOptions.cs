// Copyright (c) Mihir Dilip. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

using Microsoft.AspNetCore.Authentication;

namespace Mihir.AspNetCore.Authentication.Basic
{
	/// <summary>
	/// Inherited from <see cref="AuthenticationSchemeOptions"/> to allow extra option properties for 'Basic' authentication.
	/// </summary>
	public class BasicOptions : AuthenticationSchemeOptions
	{
		/// <summary>
		/// This is required property. It is used when challenging un-authenticated requests.
		/// </summary>
		public string Realm { get; set; }

		//public new BasicEvents Events
		//{
		//	get => (BasicEvents)base.Events;
		//	set => base.Events = value;
		//}
	}
}
