package sourcefixture

import "os"

func unsafePermissions(path string) error {
	return os.Chmod(path, 0o777)
}
