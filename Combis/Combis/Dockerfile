# Use the official .NET SDK image for building the app
FROM mcr.microsoft.com/dotnet/sdk:8.0 as build

# Set the working directory in the container
WORKDIR /app

# Copy the csproj and restore any dependencies (via NuGet)
COPY ["Combis.csproj", "Combis/"]
RUN dotnet restore "Combis/Combis.csproj"

# Copy the rest of the source code to the container
COPY . .

# Build the application
WORKDIR "/app/Combis"
RUN dotnet build "Combis.csproj" -c Release -o /app/build

# Publish the application to the /app/publish directory
RUN dotnet publish "Combis.csproj" -c Release -o /app/publish /p:UseAppHost=false

# Use the official .NET ASP.NET image for running the app
FROM mcr.microsoft.com/dotnet/aspnet:8.0 as final

# Set the working directory in the container
WORKDIR /app

# Copy the published application from the build stage
COPY --from=build /app/publish .

# Expose the port the app will run on
EXPOSE 80

# Set the entry point for the container
ENTRYPOINT ["dotnet", "CombisApp.dll"]
