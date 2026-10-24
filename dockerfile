FROM eclipse-temurin:17-jdk-jammy

WORKDIR /app

# Copy all project files into the container
COPY . .

# Compile all java files
RUN javac *.java

# Run the main class (Note: Swing apps require a display, 
# but this will run the backend logic/database tests successfully)
CMD ["java", "Main"]