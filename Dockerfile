FROM python:3.13-slim
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

# Change the working directory to the `app` directory
WORKDIR /app

# Install dependencies
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    uv sync --frozen --no-install-project

# Copy the project into the image
ADD . /app

# Sync the project
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen

# Create a startup script that runs migrations and starts the app
RUN echo '#!/bin/bash\n\
# Wait for database to be ready (if needed)\n\
# sleep 5\n\
\n\
# Run database migrations\n\
echo "Running database migrations..."\n\
uv run aerich upgrade || echo "Migration failed or already up to date"\n\
\n\
# Start the application\n\
echo "Starting application..."\n\
exec uv run uvicorn main:application --host 0.0.0.0 --port 8000\n\
' > /app/start.sh && chmod +x /app/start.sh

# Run the startup script
CMD ["/app/start.sh"]
