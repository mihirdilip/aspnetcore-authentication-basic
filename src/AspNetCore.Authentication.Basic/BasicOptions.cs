﻿// Copyright (c) Mihir Dilip. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

using Microsoft.AspNetCore.Authentication;
using System;

namespace AspNetCore.Authentication.Basic
{
    /// <summary>
    /// Options used to configure basic authentication.
    /// </summary>
    public class BasicOptions : AuthenticationSchemeOptions
	{
        /// <summary>
        /// Gets or sets the realm property. It is used with WWW-Authenticate response header when challenging un-authenticated requests.
        /// <see href="https://tools.ietf.org/html/rfc7235#section-2.2"/>
        /// </summary>
        public string Realm { get; set; }

        /// <summary>
        /// Default value is false.
        /// When set to true, it will NOT return WWW-Authenticate response header when challenging un-authenticated requests.
        /// When set to false, it will return WWW-Authenticate response header when challenging un-authenticated requests.
        /// It is normally used to disable browser prompt when doing ajax calls.
        /// <see href="https://tools.ietf.org/html/rfc7235#section-4.1"/>
        /// </summary>
        public bool SuppressWWWAuthenticateHeader { get; set; }

        /// <summary>
        /// The object provided by the application to process events raised by the basic authentication middleware.
        /// The application may implement the interface fully, or it may create an instance of BasicEvents
        /// and assign delegates only to the events it wants to process.
        /// </summary>
        public new BasicEvents Events
        {
            get => (BasicEvents)base.Events;
            set => base.Events = value;
        }

        /// <inheritdoc/>
        public override void Validate()
        {
            base.Validate();
            if (!SuppressWWWAuthenticateHeader && string.IsNullOrWhiteSpace(Realm))
            {
                throw new InvalidOperationException("Realm must be set in basic options");
            }
        }
    }
}
