using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication("cookie")
.AddCookie("cookie", options => {
	options.Events.OnRedirectToLogin = context => {
		context.Response.StatusCode = StatusCodes.Status401Unauthorized;
		return Task.CompletedTask;
	};

	options.Events.OnRedirectToAccessDenied = context => {
		context.Response.StatusCode = StatusCodes.Status403Forbidden;
		return Task.CompletedTask;
	};
});

builder.Services.AddAuthorization(builder => {
	builder.AddPolicy("admin", policyBuilder => {
		policyBuilder.RequireAuthenticatedUser()
		.AddAuthenticationSchemes("cookie")
		.RequireClaim("role", "admin");
	});
});

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.MapPost("/login", async (HttpContext context, User user) => {

	// check if the credentials are correct
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
	await context.SignOutAsync("cookie");
	return Results.Ok();
});

app.MapGet("/user", (HttpContext context) => {
	// get the value of the claim
	var value = context.User.Claims.First(c => c.Type == "role").Value;
	return Results.Ok("hello " + value);
}).RequireAuthorization("admin");

app.Run();


class User {
	public required string Email { get; set; }
	public required string Password { get; set; }
}