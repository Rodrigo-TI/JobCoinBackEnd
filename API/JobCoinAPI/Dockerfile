FROM mcr.microsoft.com/dotnet/aspnet:5.0 AS base
WORKDIR /app
EXPOSE 80

ENV ASPNETCORE_ENVIRONMENT=Development
ENV ASPNETCORE_URLS=http://*:$PORT

FROM mcr.microsoft.com/dotnet/sdk:5.0 AS build
WORKDIR /src
COPY ["JobCoinAPI.csproj", "./"]
RUN dotnet restore "JobCoinAPI.csproj"
COPY . .
WORKDIR "/src/."
RUN dotnet build "JobCoinAPI.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "JobCoinAPI.csproj" -c Release -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "JobCoinAPI.dll"]
