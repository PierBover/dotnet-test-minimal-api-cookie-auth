using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication("cookie")
.AddCookie("cookie", options => {
	// configure cookie settings
	options.Cookie.Name = "api-cookie";
	options.Cookie.MaxAge = TimeSpan.FromDays(7);
	options.Cookie.SameSite = SameSiteMode.Strict;

	// when authentication fails
	options.Events.OnRedirectToLogin = context => {
		context.Response.StatusCode = StatusCodes.Status401Unauthorized;
		return Task.CompletedTask;
	};

	// when authorization fails
	options.Events.OnRedirectToAccessDenied = context => {
		context.Response.StatusCode = StatusCodes.Status403Forbidden;
		return Task.CompletedTask;
	};

	// by default cookies will renew when 50% of the expiration time has passed
	// but to configure cookie renewal use options.Events.CheckSlidingExpiration = context => {}
	// more info: https://github.com/dotnet/aspnetcore/blob/main/src/Security/Authentication/Cookies/samples/CookieSample/Program.cs#L18-L30
});

builder.Services.AddAuthorizationBuilder()
.AddPolicy("admin", policyBuilder => {
	policyBuilder.RequireAuthenticatedUser()
	.AddAuthenticationSchemes("cookie")
	.RequireClaim("role", "admin");
});

var app = builder.Build();

// auth middlewares
app.UseAuthentication();
app.UseAuthorization();

app.MapPost("/login", async (HttpContext context, User user) => {

	// super secure authentication ;)
	if (user is not null && user.Email == "user@domain.com" && user.Password == "12345")
	{
		// create the claims for the user
		var claims = new List<Claim>{new Claim("role", "admin")};
		var identity = new ClaimsIdentity(claims, "cookie");

		// sign in with the authentication service
		// this adds the Set-Cookie HTTP header in the response with an encrypted cookie
		await context.SignInAsync("cookie", new ClaimsPrincipal(identity));

		return Results.Ok();
	}

	return Results.Unauthorized();
});

app.MapGet("/logout", async (HttpContext context) => {
	// deletes the cookie
	await context.SignOutAsync("cookie");
	return Results.Ok();
});

app.MapGet("/user", (HttpContext context) => {
	// get the auth claims from the request
	var value = context.User.Claims.First(c => c.Type == "role").Value;
	return Results.Ok("hello " + value);
}).RequireAuthorization("admin");

app.Run();


class User {
	public required string Email { get; set; }
	public required string Password { get; set; }
}