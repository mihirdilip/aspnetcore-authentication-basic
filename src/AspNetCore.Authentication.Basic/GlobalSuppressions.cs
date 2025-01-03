// This file is used by Code Analysis to maintain SuppressMessage
// attributes that are applied to this project.
// Project-level suppressions either have no target or are given
// a specific target and scoped to a namespace, type, member, etc.

using System.Diagnostics.CodeAnalysis;

[assembly: SuppressMessage("Style", "IDE0130:Namespace does not match folder structure", Justification = "Does not need to match, folder used for structural purpose only.", Scope = "namespace", Target = "~N:AspNetCore.Authentication.Basic")]
[assembly: SuppressMessage("Style", "IDE0290:Use primary constructor", Justification = "Not a fan of this.")]
[assembly: SuppressMessage("Maintainability", "CA1510:Use ArgumentNullException throw helper", Justification = "Not supported by older frameworks.")]
