# Build Stage
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

# Copy project files and restore dependencies
COPY ["Combis/Combis.csproj", "Combis/"]
COPY ["BuisnessLayer/BuisnessLayer.csproj", "BuisnessLayer/"]
COPY ["CommonLayer/CommonLayer.csproj", "CommonLayer/"]
COPY ["DAL/DAL.csproj", "DAL/"]
RUN dotnet restore "Combis/Combis.csproj"

# Copy the rest of the application and publish
COPY . .
WORKDIR /src/Combis
RUN dotnet publish "Combis.csproj" -c Release -o /app/publish

# Final Stage
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS final
WORKDIR /app
COPY --from=build /app/publish .

# Set a non-root user (optional but recommended for security)
# RUN adduser --disabled-password appuser
# USER appuser

# Expose the port the app runs on
EXPOSE 80

# Health check to ensure the app is running
HEALTHCHECK CMD curl --fail http://localhost:80/health || exit 1

ENTRYPOINT ["dotnet", "Combis.dll"]