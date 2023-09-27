import { dotnet } from './dotnet.js'

try {
    await dotnet.run();
} catch (error) {
    console.error(error);
}


