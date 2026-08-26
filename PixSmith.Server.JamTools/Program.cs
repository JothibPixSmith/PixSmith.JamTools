var builder = WebApplication.CreateBuilder(args);

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    // Lets the browser attach to the WASM runtime for client-side C# debugging.
    app.UseWebAssemblyDebugging();
}
else
{
    app.UseHsts();
    app.UseHttpsRedirection();
}

// Serves _framework/* (blazor.webassembly.js, the dotnet runtime, the app dlls).
app.UseBlazorFrameworkFiles();
app.UseStaticFiles();

var api = app.MapGroup("/api");

api.MapGet("/health", () => Results.Ok(new
{
    status = "ok",
    environment = app.Environment.EnvironmentName,
    utc = DateTimeOffset.UtcNow
}));

// Anything that isn't a file or an API route is handed to the SPA router.
app.MapFallbackToFile("index.html");

app.Run();
