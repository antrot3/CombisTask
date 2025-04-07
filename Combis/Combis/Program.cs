using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using DAL;
using DAL.Models;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Microsoft.OpenApi.Models;
using BuisnessLayer.Interface;
using BuisnessLayer;
using ServiceLayer.Interface;
using ServiceLayer.Service;
using DAL.Interface;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

// Add Identity services
builder.Services.AddIdentity<AppUser, IdentityRole<Guid>>(options =>
{
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);  // Lockout duration
    options.Lockout.MaxFailedAccessAttempts = 6;  // Max failed login attempts
    options.User.AllowedUserNameCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+";
    options.Password.RequireDigit = true;
    options.Password.RequiredLength = 8;  // Minimum password length
    options.Password.RequireLowercase = true;
    options.Password.RequireNonAlphanumeric = false;
    options.Password.RequireUppercase = true;
    options.Password.RequiredUniqueChars = 1;
})
.AddEntityFrameworkStores<ApplicationDbContext>()
.AddDefaultTokenProviders();

// JWT authentication setup
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = builder.Configuration["Jwt:ValidIssuer"],
            ValidAudience = builder.Configuration["Jwt:ValidAudience"],
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["Jwt:SymmetricSecurityKey"])),
            RoleClaimType = ClaimTypes.Role
        };
        options.Events = new JwtBearerEvents
        {
            OnAuthenticationFailed = context =>
            {
                // Log any failures for debugging
                Console.WriteLine("Authentication failed: " + context.Exception);
                return Task.CompletedTask;
            },
            OnTokenValidated = context =>
            {
                // This can be useful for debugging if the token is being validated correctly
                Console.WriteLine("Token validated.");
                return Task.CompletedTask;
            },
            OnForbidden = context =>
            {
                // Log any forbidden requests for debugging
                Console.WriteLine("Forbidden request.");
                return Task.CompletedTask;
            },
            OnMessageReceived = context =>
            {
                // Log any forbidden requests for debugging
                Console.WriteLine("message recived");
                return Task.CompletedTask;
            },

        };
    });

// Add authorization services
builder.Services.AddAuthorization();

// Register IUserRepository and UserRepository
builder.Services.AddScoped<IUserRepository, UserRepository>();

// Register IUserService and UserService
builder.Services.AddScoped<IUserService, UserService>();

// Register IAppUserService and AppUserService
builder.Services.AddScoped<IAppUserService, AppUserService>();

// Register IJwtService and JwtService
builder.Services.AddScoped<IJwtService, JwtService>();  // Registering IJwtService

// Register the controllers
builder.Services.AddControllers();

// Add services for Swagger
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options =>
{
    options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Name = "Authorization",
        Type = SecuritySchemeType.ApiKey,
        In = ParameterLocation.Header,
        Scheme = "Bearer",
        BearerFormat = "JWT",
        Description = "Enter 'Bearer' followed by a space and the JWT token."
    });

    options.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            new string[] {}
        }
    });
});

var app = builder.Build();

// Apply migrations on startup
using (var scope = app.Services.CreateScope())
{
    var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
    dbContext.Database.Migrate();  // Apply any pending migrations to the database
}

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

// Enable routing and controllers
app.UseRouting();

// Enable authentication and authorization middleware
app.UseAuthentication(); // Make sure this is before UseAuthorization
app.UseAuthorization();  // This should be after UseAuthentication

// Map API controllers
app.MapControllers();

// Run the app
app.Run();
