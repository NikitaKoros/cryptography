package numbertheory

// Service предоставляет stateless-функционал для операций теории чисел
type Service struct{}

// NewService создает новый экземпляр сервиса
func NewService() *Service {
	return &Service{}
}
