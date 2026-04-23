using Microsoft.EntityFrameworkCore;
using SmartEventMVC.Middleware;
using SmartEventMVC.Models;
using SmartEventMVC.Services;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews();

// The demo website calls the local PySpark WAF API before MVC controllers process requests.
builder.Services.Configure<WafOptions>(builder.Configuration.GetSection("Waf"));
builder.Services.AddHttpClient<WafClient>();

// Your DbContext.
builder.Services.AddDbContext<SmartEventDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

// Add session support for login and booking flow.
builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(30);
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

// app.UseAuthentication();
// app.UseAuthorization();

app.UseSession();

// This middleware blocks obvious malicious requests and lets clean traffic continue.
// It runs after session setup so the layout can show visible WAF proof for allowed requests.
app.UseMiddleware<WafInspectionMiddleware>();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
